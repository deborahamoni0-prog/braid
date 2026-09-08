//! Source scanning: find every Soroban storage access and the local bindings
//! that feed its key expression.
//!
//! This pass is deliberately syntactic. It does not resolve types or expand
//! macros, so anything it cannot see it records as unresolvable rather than
//! guessing. See `classify` for what happens to what it finds.

use crate::model::{Access, Durability};
use quote::ToTokens;
use std::collections::HashSet;
use std::path::Path;
use syn::visit::Visit;

/// Where an argument to a key constructor came from, as far as syntax shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgOrigin {
    /// A named binding — a parameter, or a local we can look up.
    Ident(String),
    /// Something we could not reduce to a name, with the expression text.
    Opaque(String),
}

/// A storage access site, before classification.
#[derive(Debug, Clone)]
pub struct RawAccess {
    pub line: usize,
    pub column: usize,
    pub durability: Durability,
    pub access: Access,
    pub key_expr: String,
    pub key_root: String,
    pub key_args: Vec<ArgOrigin>,
}

/// A `let` binding, recorded so we can tell whether a key parameter was
/// supplied by the caller or minted from shared state.
#[derive(Debug, Clone)]
pub struct LetBinding {
    pub name: String,
    pub line: usize,
    /// Set when the initialiser reads a storage key directly.
    pub from_storage_key: Option<String>,
    /// Set when the initialiser calls a function, which may turn out to be a
    /// counter. Resolved crate-wide in `classify`.
    pub from_call: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub file: String,
    pub line: usize,
    /// A public function inside a `#[contractimpl]` block, or a public free
    /// function in a contract crate.
    pub entry_point: bool,
    pub params: HashSet<String>,
    pub lets: Vec<LetBinding>,
    pub accesses: Vec<RawAccess>,
}

impl FunctionInfo {
    /// Whether this looks like an administrative or configuration path.
    ///
    /// Heuristic, and it only moves severity between critical and warning —
    /// never between "finding" and "no finding". A write to a shared entry in
    /// `set_admin` is real, it is just expected to run rarely.
    pub fn is_admin_path(&self) -> bool {
        const ADMIN_PREFIXES: &[&str] = &[
            "set_",
            "init",
            "__constructor",
            "initialize",
            "upgrade",
            "migrate",
            "configure",
            "config",
            "pause",
            "unpause",
            "transfer_admin",
            "set_config",
            "rotate",
            "register_asset",
        ];
        let n = self.name.as_str();
        ADMIN_PREFIXES.iter().any(|p| n.starts_with(p) || n == *p)
    }
}

#[derive(Debug, Default)]
pub struct ScanResult {
    pub functions: Vec<FunctionInfo>,
    pub files_scanned: usize,
    /// Files that failed to parse, with the reason. Reported, never silent.
    pub parse_errors: Vec<(String, String)>,
}

/// Scan a file or directory of Rust sources.
pub fn scan(root: &Path) -> ScanResult {
    let mut out = ScanResult::default();
    let files: Vec<_> = if root.is_file() {
        vec![root.to_path_buf()]
    } else {
        walkdir::WalkDir::new(root)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .filter(|p| p.extension().map(|x| x == "rs").unwrap_or(false))
            // Skip build output and vendored code; scanning `target/` finds
            // thousands of irrelevant accesses in dependencies.
            .filter(|p| {
                !p.components().any(|c| {
                    let s = c.as_os_str().to_string_lossy();
                    s == "target" || s == ".git" || s == "node_modules"
                })
            })
            .collect()
    };

    for path in files {
        let display = path.display().to_string();
        let src = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                out.parse_errors.push((display, e.to_string()));
                continue;
            }
        };
        match syn::parse_file(&src) {
            Ok(ast) => {
                out.files_scanned += 1;
                let mut v = FileVisitor::new(&display);
                v.visit_file(&ast);
                out.functions.extend(v.functions);
            }
            Err(e) => out.parse_errors.push((display, e.to_string())),
        }
    }
    out
}

struct FileVisitor {
    file: String,
    functions: Vec<FunctionInfo>,
    /// True while inside an impl block carrying `#[contractimpl]`.
    in_contract_impl: bool,
}

impl FileVisitor {
    fn new(file: &str) -> Self {
        Self {
            file: file.to_string(),
            functions: Vec::new(),
            in_contract_impl: false,
        }
    }

    fn record_fn(&mut self, sig: &syn::Signature, block: &syn::Block, is_pub: bool) {
        let mut params = HashSet::new();
        for arg in &sig.inputs {
            if let syn::FnArg::Typed(pat_type) = arg {
                collect_pat_idents(&pat_type.pat, &mut params);
            }
        }

        let mut body = BodyVisitor::default();
        body.visit_block(block);

        let span = sig.ident.span();
        self.functions.push(FunctionInfo {
            name: sig.ident.to_string(),
            file: self.file.clone(),
            line: span.start().line,
            entry_point: is_pub && self.in_contract_impl,
            params,
            lets: body.lets,
            accesses: body.accesses,
        });
    }
}

impl<'ast> Visit<'ast> for FileVisitor {
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let was = self.in_contract_impl;
        self.in_contract_impl = node.attrs.iter().any(|a| a.path().is_ident("contractimpl"));
        for item in &node.items {
            if let syn::ImplItem::Fn(f) = item {
                let is_pub = matches!(f.vis, syn::Visibility::Public(_));
                self.record_fn(&f.sig, &f.block, is_pub);
            }
        }
        self.in_contract_impl = was;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let is_pub = matches!(node.vis, syn::Visibility::Public(_));
        self.record_fn(&node.sig, &node.block, is_pub);
    }
}

#[derive(Default)]
struct BodyVisitor {
    lets: Vec<LetBinding>,
    accesses: Vec<RawAccess>,
}

impl<'ast> Visit<'ast> for BodyVisitor {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        let mut names = HashSet::new();
        collect_pat_idents(&node.pat, &mut names);

        if let Some(init) = &node.init {
            let from_storage_key = storage_get_key(&init.expr);
            let from_call = called_fn_name(&init.expr);
            let line = node.let_token.span.start().line;
            for name in names {
                self.lets.push(LetBinding {
                    name,
                    line,
                    from_storage_key: from_storage_key.clone(),
                    from_call: from_call.clone(),
                });
            }
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if let Some((durability, access)) = storage_target(node) {
            if let Some(key_expr) = node.args.first() {
                let stripped = strip_refs(key_expr);
                let (key_root, key_args) = decompose_key(stripped);
                let span = node.method.span();
                self.accesses.push(RawAccess {
                    line: span.start().line,
                    column: span.start().column + 1,
                    durability,
                    access,
                    key_expr: tokens_to_string(stripped),
                    key_root,
                    key_args,
                });
            } else if node.method == "extend_ttl" {
                // instance().extend_ttl(a, b) has no key argument: the key is
                // the contract instance itself.
                let span = node.method.span();
                self.accesses.push(RawAccess {
                    line: span.start().line,
                    column: span.start().column + 1,
                    durability,
                    access,
                    key_expr: "<contract instance>".into(),
                    key_root: "<instance>".into(),
                    key_args: vec![],
                });
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

/// Recognise `env.storage().persistent().set(...)` and friends.
///
/// Returns the durability and access kind when the receiver chain really is a
/// Soroban storage accessor. Matching on the chain rather than on the method
/// name alone keeps `map.get(k)` and `vec.set(i, v)` out of the results.
fn storage_target(node: &syn::ExprMethodCall) -> Option<(Durability, Access)> {
    let access = Access::from_method(&node.method.to_string())?;

    let syn::Expr::MethodCall(inner) = &*node.receiver else {
        return None;
    };
    let durability = match inner.method.to_string().as_str() {
        "instance" => Durability::Instance,
        "persistent" => Durability::Persistent,
        "temporary" => Durability::Temporary,
        _ => return None,
    };

    // The receiver of `.instance()` must itself be a `.storage()` call.
    let syn::Expr::MethodCall(storage) = &*inner.receiver else {
        return None;
    };
    if storage.method != "storage" {
        return None;
    }
    Some((durability, access))
}

/// If this expression reads a storage key, return that key's root.
///
/// Used to decide whether a `let` binding was minted from shared state.
fn storage_get_key(expr: &syn::Expr) -> Option<String> {
    struct Finder(Option<String>);
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if self.0.is_none() {
                if let Some((_, Access::Read)) = storage_target(node) {
                    if let Some(k) = node.args.first() {
                        let (root, _) = decompose_key(strip_refs(k));
                        self.0 = Some(root);
                    }
                }
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }
    let mut f = Finder(None);
    f.visit_expr(expr);
    f.0
}

/// The name of a function called anywhere in this expression, if any.
fn called_fn_name(expr: &syn::Expr) -> Option<String> {
    struct Finder(Option<String>);
    impl<'ast> Visit<'ast> for Finder {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if self.0.is_none() {
                if let syn::Expr::Path(p) = &*node.func {
                    if let Some(seg) = p.path.segments.last() {
                        self.0 = Some(seg.ident.to_string());
                    }
                }
            }
            syn::visit::visit_expr_call(self, node);
        }
    }
    let mut f = Finder(None);
    f.visit_expr(expr);
    f.0
}

/// Split `DataKey::Balance(addr)` into `("DataKey::Balance", [Ident("addr")])`.
fn decompose_key(expr: &syn::Expr) -> (String, Vec<ArgOrigin>) {
    match expr {
        syn::Expr::Path(p) => (path_string(&p.path), vec![]),
        syn::Expr::Call(call) => {
            let root = match &*call.func {
                syn::Expr::Path(p) => path_string(&p.path),
                other => tokens_to_string(other),
            };
            let args = call.args.iter().map(arg_origin).collect();
            (root, args)
        }
        syn::Expr::Struct(s) => {
            let root = path_string(&s.path);
            let args = s.fields.iter().map(|f| arg_origin(&f.expr)).collect();
            (root, args)
        }
        syn::Expr::Lit(l) => (tokens_to_string(l), vec![]),
        syn::Expr::Macro(m) => {
            // symbol_short!("balance") and similar are constant keys.
            (tokens_to_string(m), vec![])
        }
        syn::Expr::Tuple(t) => {
            let args = t.elems.iter().map(arg_origin).collect();
            ("<tuple>".to_string(), args)
        }
        other => (
            tokens_to_string(other),
            vec![ArgOrigin::Opaque(tokens_to_string(other))],
        ),
    }
}

/// Reduce an argument to the name it ultimately comes from, seeing through
/// references, `.clone()`, `.into()` and casts.
fn arg_origin(expr: &syn::Expr) -> ArgOrigin {
    match strip_refs(expr) {
        syn::Expr::Path(p) => {
            if p.path.segments.len() == 1 {
                ArgOrigin::Ident(p.path.segments[0].ident.to_string())
            } else {
                ArgOrigin::Opaque(path_string(&p.path))
            }
        }
        syn::Expr::MethodCall(m) => {
            // `addr.clone()` is still `addr`; `env.ledger().sequence()` is not
            // reducible to a binding and must stay opaque.
            const TRANSPARENT: &[&str] =
                &["clone", "into", "to_owned", "as_ref", "copied", "cloned"];
            if TRANSPARENT.contains(&m.method.to_string().as_str()) {
                arg_origin(&m.receiver)
            } else {
                ArgOrigin::Opaque(tokens_to_string(expr))
            }
        }
        syn::Expr::Cast(c) => arg_origin(&c.expr),
        other => ArgOrigin::Opaque(tokens_to_string(other)),
    }
}

fn strip_refs(expr: &syn::Expr) -> &syn::Expr {
    match expr {
        syn::Expr::Reference(r) => strip_refs(&r.expr),
        syn::Expr::Paren(p) => strip_refs(&p.expr),
        syn::Expr::Group(g) => strip_refs(&g.expr),
        other => other,
    }
}

fn path_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn tokens_to_string(t: &impl ToTokens) -> String {
    let s = t.to_token_stream().to_string();
    // `DataKey :: Balance (addr)` reads badly in a report.
    s.replace(" :: ", "::")
        .replace(" (", "(")
        .replace("( ", "(")
        .replace(" )", ")")
        .replace(" ,", ",")
        .replace(" . ", ".")
}

fn collect_pat_idents(pat: &syn::Pat, out: &mut HashSet<String>) {
    match pat {
        syn::Pat::Ident(i) => {
            out.insert(i.ident.to_string());
        }
        syn::Pat::Type(t) => collect_pat_idents(&t.pat, out),
        syn::Pat::Reference(r) => collect_pat_idents(&r.pat, out),
        syn::Pat::Tuple(t) => t.elems.iter().for_each(|p| collect_pat_idents(p, out)),
        syn::Pat::TupleStruct(t) => t.elems.iter().for_each(|p| collect_pat_idents(p, out)),
        syn::Pat::Struct(s) => s
            .fields
            .iter()
            .for_each(|f| collect_pat_idents(&f.pat, out)),
        syn::Pat::Or(o) => o.cases.iter().for_each(|p| collect_pat_idents(p, out)),
        _ => {}
    }
}
