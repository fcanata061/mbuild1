#include <bits/stdc++.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <vector>
#include <queue>
#include <openssl/sha.h>

namespace fs = std::filesystem;

// ========================= Configurações globais =========================
struct Config {
    std::string home = "/var/lib/pkgmgr";
    std::string sources = home + "/sources";
    std::string work = home + "/work";
    std::string logs = home + "/logs";
    std::string repo = home + "/repo";
    std::string bin = home + "/bin";
    std::string staging = home + "/staging";
    std::string destdir = "/";
    int jobs = 4;
    std::string strip_flags = "-s";
    std::string package_format = "xz";
    std::string git_remote = "";
    std::string git_branch = "main";
} CFG;

// ========================= Estruturas =========================
struct PackageMeta {
    std::string name;
    std::string version;
    std::vector<std::string> deps;
    std::string sha256;
    std::string source_url;
};

// Banco de dados local de pacotes instalados
struct DB {
    std::map<std::string, PackageMeta> installed;
} DBSTATE;

// ========================= Funções utilitárias =========================
static std::string sha256sum(const std::string &filename) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char buf[8192];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    std::ifstream file(filename, std::ios::binary);
    if (!file) return "";
    while (file.good()) {
        file.read(buf, sizeof(buf));
        SHA256_Update(&sha256, buf, file.gcount());
    }
    SHA256_Final(hash, &sha256);
    std::ostringstream result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        result << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return result.str();
}

static bool runCommand(const std::string &cmd) {
    std::cout << "[CMD] " << cmd << "\n";
    int ret = system(cmd.c_str());
    return ret == 0;
}

// ========================= Banco de dados =========================
static void db_load() {
    std::string dbfile = CFG.home + "/db.txt";
    std::ifstream in(dbfile);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        PackageMeta meta;
        ss >> meta.name >> meta.version;
        std::string deps;
        ss >> deps;
        std::stringstream depstream(deps);
        std::string d;
        while (std::getline(depstream, d, ',')) {
            if (!d.empty()) meta.deps.push_back(d);
        }
        DBSTATE.installed[meta.name] = meta;
    }
}

static void db_save() {
    std::string dbfile = CFG.home + "/db.txt";
    std::ofstream out(dbfile);
    for (auto &p : DBSTATE.installed) {
        out << p.second.name << " " << p.second.version << " ";
        for (size_t i = 0; i < p.second.deps.size(); i++) {
            out << p.second.deps[i];
            if (i + 1 < p.second.deps.size()) out << ",";
        }
        out << "\n";
    }
}

// ========================= Parser de metadados =========================
static PackageMeta parseMeta(const std::string &path) {
    PackageMeta meta;
    std::ifstream in(path);
    if (!in) return meta;
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("name=", 0) == 0) meta.name = line.substr(5);
        else if (line.rfind("version=", 0) == 0) meta.version = line.substr(8);
        else if (line.rfind("deps=", 0) == 0) {
            std::string deps = line.substr(5);
            std::stringstream ss(deps);
            std::string d;
            while (std::getline(ss, d, ',')) {
                if (!d.empty()) meta.deps.push_back(d);
            }
        } else if (line.rfind("sha256=", 0) == 0) meta.sha256 = line.substr(7);
        else if (line.rfind("source=", 0) == 0) meta.source_url = line.substr(7);
    }
    return meta;
}

// ========================= Resolução de dependências =========================
static std::vector<std::string> topoSort(const std::map<std::string, PackageMeta> &metas, const std::string &target) {
    std::map<std::string, std::set<std::string>> graph;
    std::map<std::string, int> indeg;

    // Construir grafo
    for (auto &p : metas) {
        for (auto &d : p.second.deps) {
            graph[d]; // garante nó
            graph[p.first].insert(d);
        }
    }
    for (auto &g : graph) {
        if (!indeg.count(g.first)) indeg[g.first] = 0;
        for (auto &d : g.second) indeg[d]++;
    }

    std::queue<std::string> q;
    for (auto &p : indeg) if (p.second == 0) q.push(p.first);

    std::vector<std::string> order;
    while (!q.empty()) {
        std::string u = q.front(); q.pop();
        order.push_back(u);
        for (auto &d : graph[u]) {
            if (--indeg[d] == 0) q.push(d);
        }
    }

    // manter apenas dependências do alvo
    std::set<std::string> needed;
    std::function<void(const std::string&)> dfs = [&](const std::string &pkg){
        if (needed.count(pkg)) return;
        needed.insert(pkg);
        for (auto &d : metas.at(pkg).deps) dfs(d);
    };
    dfs(target);

    std::vector<std::string> filtered;
    for (auto &p : order) if (needed.count(p)) filtered.push_back(p);
    return filtered;
}
// ========================= Parte 2 — helpers extra & ações =========================

static void ensureDir(const fs::path& p){ std::error_code ec; fs::create_directories(p, ec); }
static bool fileExists(const fs::path& p){ std::error_code ec; return fs::exists(p, ec); }

// flags ajustáveis por CLI
static bool G_USE_FAKEROOT = false;
static bool G_DO_STRIP = true;

// captura saída de comando
static std::string execCapture(const std::string& cmd){
    std::array<char, 4096> buf{};
    std::string out;
    FILE* pipe = popen(cmd.c_str(), "r");
    if(!pipe) return out;
    while(fgets(buf.data(), buf.size(), pipe)) out.append(buf.data());
    pclose(pipe);
    return out;
}

static std::string now_ts(const char* fmt="%Y%m%d-%H%M%S"){
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char b[64]; std::strftime(b, sizeof(b), fmt, &tm);
    return b;
}

// logging simples
static void logInfo(const std::string& s){ std::cerr<<"[*] "<<s<<"\n"; }
static void logWarn(const std::string& s){ std::cerr<<"[!] "<<s<<"\n"; }
static void logErr (const std::string& s){ std::cerr<<"[x] "<<s<<"\n"; }

// caminhos auxiliares
static fs::path metaPath(const std::string& name){ return fs::path(CFG.repo) / (name + ".meta"); }
static fs::path filesPath(const std::string& name){ return fs::path(CFG.repo) / (name + ".files"); }
static fs::path stageDir (const std::string& name){ return fs::path(CFG.staging) / name; }
static fs::path workDir  (const std::string& name){ return fs::path(CFG.work) / name; }
static fs::path logDir   (const std::string& name){ return fs::path(CFG.logs) / name; }

static bool isUrl(const std::string& s){
    return s.rfind("http://",0)==0 || s.rfind("https://",0)==0;
}
static bool isGit(const std::string& s){
    if(s.rfind("git@",0)==0) return true;
    if(s.rfind("ssh://",0)==0) return true;
    if(s.rfind("https://",0)==0 && s.find(".git")!=std::string::npos) return true;
    if(s.size()>4 && s.substr(s.size()-4)==".git") return true;
    return false;
}
static std::string detectArchiveType(const std::string& f){
    if(std::regex_search(f, std::regex("\\.(tar\\.(gz|bz2|xz|zst))$"))) return "tar";
    if(std::regex_search(f, std::regex("\\.(tgz|tbz2|txz)$"))) return "tar";
    if(std::regex_search(f, std::regex("\\.zip$"))) return "zip";
    if(std::regex_search(f, std::regex("\\.7z$"))) return "7z";
    return "dir";
}

// hooks: $home/hooks/<phase>/*
static void runHooks(const std::string& phase, const std::string& name){
    fs::path hooksDir = fs::path(CFG.home)/"hooks"/phase;
    if(!fileExists(hooksDir)) return;
    for(auto& e: fs::directory_iterator(hooksDir)){
        if(!e.is_regular_file()) continue;
        std::string cmd = "'" + e.path().string() + "' '" + name + "'";
        runCommand(cmd);
    }
}

// carrega meta de um pacote no repo
static bool loadMetaFile(const std::string& name, PackageMeta& out){
    fs::path mp = metaPath(name);
    if(!fileExists(mp)){ logErr("Meta não encontrado: " + mp.string()); return false; }
    out = parseMeta(mp.string());
    if(out.name.empty()) out.name = name;
    return true;
}

// coleta recursivamente os metas necessários
static void collectMetasRec(const std::string& pkg,
                            std::map<std::string, PackageMeta>& metas,
                            std::set<std::string>& vis)
{
    if(vis.count(pkg)) return;
    vis.insert(pkg);
    PackageMeta m;
    if(!loadMetaFile(pkg, m)) return;
    metas[m.name] = m;
    for(auto& d: m.deps) collectMetasRec(d, metas, vis);
}

static std::map<std::string, PackageMeta> collectMetas(const std::string& root){
    std::map<std::string, PackageMeta> metas;
    std::set<std::string> vis;
    collectMetasRec(root, metas, vis);
    return metas;
}

// primeiro subdir se houver só 1
static fs::path firstOrOnlySubdir(const fs::path& root){
    int dirs=0; fs::path last;
    for(auto& e: fs::directory_iterator(root)){
        if(e.is_directory()){ dirs++; last = e.path(); }
    }
    if(dirs==1) return last;
    return root;
}

// lista de arquivos de um stage (relativa)
static void record_filelist_from_stage(const std::string& name, const fs::path& stage){
    ensureDir(CFG.repo);
    std::ofstream out(filesPath(name));
    if(!out) return;
    auto base = stage.string();
    for(auto& e: fs::recursive_directory_iterator(stage)){
        if(!e.is_regular_file() && !e.is_symlink()) continue;
        std::string full = e.path().string();
        if(full.rfind(base,0)==0){
            std::string rel = full.substr(base.size());
            if(!rel.empty() && rel[0]=='/') rel.erase(rel.begin());
            out << rel << "\n";
        }
    }
}

// strip ELF (no staging)
static void do_strip_stage(const fs::path& stage){
    if(!G_DO_STRIP) return;
    std::string cmd =
        "bash -lc '"
        "find \"" + stage.string() + "\" -type f -exec sh -c '"
        "mt=$(file -b --mime-type \"$1\"); "
        "if [ \"$mt\" = application/x-executable ] || "
        "[ \"$mt\" = application/x-pie-executable ] || "
        "[ \"$mt\" = application/x-sharedlib ]; then "
        "strip " + CFG.strip_flags + " \"$1\" || true; "
        "fi' _ {} \\;"
        "'";
    runCommand(cmd);
}

// empacotar stage -> repo/<name>-<ts>.tar.<xz|zst>
static fs::path package_stage(const std::string& name, const fs::path& stage){
    ensureDir(CFG.repo);
    std::string ts = now_ts();
    fs::path pkg = fs::path(CFG.repo)/(name + "-" + ts + ".tar." + (CFG.package_format=="xz"?"xz":"zst"));
    std::string tarcmd;
    if(CFG.package_format=="xz")
        tarcmd = "tar -C '" + stage.string() + "' -Jcf '" + pkg.string() + "' .";
    else
        tarcmd = "tar -C '" + stage.string() + "' -I 'zstd -T0 -19' -cf '" + pkg.string() + "' .";
    if(!runCommand(tarcmd)){ logErr("Falha ao empacotar stage"); return ""; }
    return pkg;
}

// instalar stage no sistema (destdir)
static bool install_stage_to_system(const fs::path& stage){
    std::string cmd = "tar -C '" + stage.string() + "' -cpf - . | ";
    if(G_USE_FAKEROOT) cmd += "fakeroot ";
    cmd += "tar -C '" + CFG.destdir + "' -xpf -";
    return runCommand(cmd);
}

// conflito de arquivos com pacotes já instalados (usa .files do repo)
static bool checkFileConflicts(const std::string& name, const fs::path& stage){
    // coleta alvos que serão escritos
    std::set<std::string> will;
    auto base = stage.string();
    for(auto& e: fs::recursive_directory_iterator(stage)){
        if(!e.is_regular_file() && !e.is_symlink()) continue;
        std::string full = e.path().string();
        if(full.rfind(base,0)==0){
            std::string rel = full.substr(base.size());
            if(!rel.empty() && rel[0]=='/') rel.erase(rel.begin());
            will.insert(rel);
        }
    }
    // checa em todos os .files
    for(auto& ent: fs::directory_iterator(CFG.repo)){
        if(ent.path().extension()!=".files") continue;
        std::string other = ent.path().stem().string();
        if(other==name) continue;
        std::ifstream in(ent.path());
        std::string rel;
        while(std::getline(in, rel)){
            if(will.count(rel)){
                logErr("Conflito de arquivo: " + rel + " já pertence a " + other);
                return false;
            }
        }
    }
    return true;
}

// ========================= Ações =========================

// fetch: SRC pode ser url (curl), git, ou diretório local
static int action_fetch(const std::string& src, const std::optional<std::string>& nameOpt, const std::optional<std::string>& sha){
    ensureDir(CFG.sources); ensureDir(CFG.logs);
    std::string name;
    if(nameOpt) name = *nameOpt;
    else{
        // usa basename
        auto pos = src.find_last_of('/');
        name = (pos==std::string::npos) ? src : src.substr(pos+1);
        if(auto p = name.find(".git"); p!=std::string::npos) name = name.substr(0,p);
    }

    fs::path logf = logDir(name)/(now_ts()+"-fetch.log");
    ensureDir(logf.parent_path());

    runHooks("pre-fetch", name);

    int rc = 0;
    if(isGit(src)){
        fs::path dst = fs::path(CFG.sources)/name;
        if(fileExists(dst))
            rc = runCommand("git -C '" + dst.string() + "' pull --ff-only") ? 0:1;
        else
            rc = runCommand("git clone --depth 1 '" + src + "' '" + dst.string() + "'") ? 0:1;
        if(rc==0) logInfo("Git OK: " + name);
    } else if(isUrl(src)){
        fs::path out = fs::path(CFG.sources) / (name);
        if(!fileExists(out)){
            rc = runCommand("curl -L --fail -o '" + out.string() + "' '" + src + "'") ? 0:1;
        }else{
            logInfo("Usando cache existente: " + out.string());
        }
        if(rc==0 && sha){
            std::string sum = sha256sum(out.string());
            if(sum != *sha){ logErr("SHA256 não confere"); rc=1; }
        }
    } else {
        // diretório local -> copia
        fs::path dst = fs::path(CFG.sources)/name;
        ensureDir(dst);
        rc = runCommand("cp -a '" + src + "'/* '" + dst.string() + "'/") ? 0:1;
    }

    runHooks("post-fetch", name);
    return rc;
}

static int action_extract(const std::string& input, const std::optional<std::string>& nameOpt){
    ensureDir(CFG.work); ensureDir(CFG.logs);
    std::string name = nameOpt.value_or([&]{
        auto pos = input.find_last_of('/'); return (pos==std::string::npos)? input : input.substr(pos+1);
    }());
    fs::path outdir = workDir(name); ensureDir(outdir);

    runHooks("pre-extract", name);

    std::string kind = detectArchiveType(input);
    int rc=0;
    if(kind=="tar")      rc = runCommand("tar -C '" + outdir.string() + "' -xf '" + input + "'")?0:1;
    else if(kind=="zip") rc = runCommand("unzip -q -d '" + outdir.string() + "' '" + input + "'")?0:1;
    else if(kind=="7z")  rc = runCommand("7z x -o'" + outdir.string() + "' '" + input + "'")?0:1;
    else                 rc = runCommand("cp -a '" + fs::path(input).string() + "'/* '" + outdir.string() + "'/")?0:1;

    runHooks("post-extract", name);
    return rc;
}

static int action_build(const std::string& name){
    ensureDir(CFG.logs);
    runHooks("pre-build", name);

    fs::path srcdir = firstOrOnlySubdir(workDir(name));
    auto runIn = [&](const std::string& c){ return runCommand("bash -lc 'cd " + srcdir.string() + " && " + c + "'"); };

    int rc=0;
    if(fileExists(srcdir/"build.sh")){
        rc = runIn("chmod +x build.sh && ./build.sh -j" + std::to_string(CFG.jobs))?0:1;
    } else if(fileExists(srcdir/"autogen.sh")){
        rc = runIn("chmod +x autogen.sh && ./autogen.sh && ./configure --prefix=/usr && make -j"+std::to_string(CFG.jobs))?0:1;
    } else if(fileExists(srcdir/"configure")){
        rc = runIn("./configure --prefix=/usr && make -j"+std::to_string(CFG.jobs))?0:1;
    } else if(fileExists(srcdir/"CMakeLists.txt")){
        rc = runIn("mkdir -p build && cd build && cmake -DCMAKE_INSTALL_PREFIX=/usr .. && make -j"+std::to_string(CFG.jobs))?0:1;
    } else if(fileExists(srcdir/"meson.build")){
        rc = runIn("meson setup build --prefix=/usr && ninja -C build -j"+std::to_string(CFG.jobs))?0:1;
    } else if(fileExists(srcdir/"setup.py")){
        rc = runIn("python3 setup.py build")?0:1;
    } else if(fileExists(srcdir/"pyproject.toml")){
        rc = runIn("pip3 wheel . -w dist")?0:1;
    } else if(fileExists(srcdir/"Cargo.toml")){
        rc = runIn("cargo build --release -j"+std::to_string(CFG.jobs))?0:1;
    } else if(fileExists(srcdir/"go.mod")){
        rc = runIn("go build ./...")?0:1;
    } else if(fileExists(srcdir/"Makefile")){
        rc = runIn("make -j"+std::to_string(CFG.jobs))?0:1;
    } else {
        logWarn("Nenhum sistema de build detectado.");
    }

    runHooks("post-build", name);
    return rc;
}

static int action_test(const std::string& name){
    runHooks("pre-test", name);
    fs::path srcdir = firstOrOnlySubdir(workDir(name));
    auto runIn = [&](const std::string& c){ return runCommand("bash -lc 'cd " + srcdir.string() + " && " + c + "'"); };
    int rc=0;
    if(fileExists(srcdir/"Makefile")) rc = (runIn("make check || make test || true")?0:1);
    else if(fileExists(srcdir/"build"/"build.ninja")) rc = (runIn("ninja -C build test || true")?0:1);
    else if(fileExists(srcdir/"Cargo.toml")) rc = (runIn("cargo test || true")?0:1);
    else logWarn("Nenhum teste encontrado.");
    runHooks("post-test", name);
    return rc;
}

// instala no STAGING (não no sistema ainda)
static int stage_install(const std::string& name, fs::path& out_stage){
    fs::path srcdir = firstOrOnlySubdir(workDir(name));
    fs::path stage = stageDir(name); ensureDir(stage);
    out_stage = stage;

    runHooks("pre-install", name);

    auto runIn = [&](const std::string& c){ return runCommand("bash -lc 'cd " + srcdir.string() + " && " + c + "'"); };

    int rc=0;
    if(fileExists(srcdir/"build"/"build.ninja")){
        rc = runIn("ninja -C build install DESTDIR='" + stage.string() + "'")?0:1;
    } else if(fileExists(srcdir/"CMakeLists.txt") && fileExists(srcdir/"build")){
        rc = runIn("cd build && make install DESTDIR='" + stage.string() + "'")?0:1;
    } else if(fileExists(srcdir/"setup.py")){
        rc = runIn("python3 setup.py install --root='" + stage.string() + "' --prefix=/usr")?0:1;
    } else if(fileExists(srcdir/"pyproject.toml")){
        rc = runIn("pip3 install . --prefix=/usr --root='" + stage.string() + "'")?0:1;
    } else if(fileExists(srcdir/"Cargo.toml")){
        rc = runIn("cargo build --release -j"+std::to_string(CFG.jobs))?0:1;
        if(rc==0){
            std::string copyBins =
                "bash -lc 'mkdir -p \"" + stage.string() + "/usr/bin\"; "
                "for f in target/release/*; do "
                "  if [ -f \"$f\" ] && file -b \"$f\" | grep -qi executable; then cp -a \"$f\" \"" + stage.string() + "/usr/bin/\"; fi; "
                "done'";
            rc = runCommand(copyBins)?0:1;
        }
    } else if(fileExists(srcdir/"go.mod")){
        rc = runIn("go build ./...")?0:1;
        if(rc==0){
            std::string copyBins =
                "bash -lc 'mkdir -p \"" + stage.string() + "/usr/bin\"; "
                "for f in $(find . -maxdepth 1 -type f); do "
                "  if file -b \"$f\" | grep -qi executable; then cp -a \"$f\" \"" + stage.string() + "/usr/bin/\"; fi; "
                "done'";
            rc = runCommand(copyBins)?0:1;
        }
    } else {
        rc = runIn("make install DESTDIR='" + stage.string() + "'")?0:1;
    }

    return rc;
}

static int action_package(const std::string& name){
    fs::path stage;
    if(!fileExists(stageDir(name)) || fs::is_empty(stageDir(name))){
        int rc = stage_install(name, stage);
        if(rc!=0){ logErr("Falha ao preparar staging para pacote"); return rc; }
    } else {
        stage = stageDir(name);
        runHooks("pre-package", name);
    }

    do_strip_stage(stage);

    fs::path pkgfile = package_stage(name, stage);
    if(pkgfile.empty()) return 1;

    record_filelist_from_stage(name, stage);

    runHooks("post-package", name);
    logInfo("Pacote criado (sem instalar): " + pkgfile.string());
    return 0;
}

static int action_install_one(const std::string& name){
    // build + stage + strip + package + filelist + install to system
    int rc=0;
    rc = action_build(name); if(rc!=0) return rc;
    rc = action_test(name);  if(rc!=0) logWarn("Testes falharam/ausentes — seguindo.");

    fs::path stage;
    rc = stage_install(name, stage); if(rc!=0){ logErr("Falha ao instalar no staging"); return rc; }

    // checa conflitos
    if(!checkFileConflicts(name, stage)){ logErr("Conflitos detectados"); return 1; }

    do_strip_stage(stage);

    fs::path pkgfile = package_stage(name, stage);
    if(pkgfile.empty()) return 1;

    record_filelist_from_stage(name, stage);

    // instala no sistema
    if(!install_stage_to_system(stage)){ logErr("Falha ao instalar no destino"); return 1; }

    runHooks("post-install", name);

    // atualiza DB de instalados
    PackageMeta m; if(loadMetaFile(name, m)){
        DBSTATE.installed[name] = m; db_save();
    }
    logInfo("Instalação concluída: " + name);
    return 0;
}

// remove usando .files
static int action_remove(const std::string& name){
    runHooks("pre-remove", name);
    fs::path list = filesPath(name);
    if(!fileExists(list)){ logErr("Lista de arquivos não encontrada: " + list.string()); return 1; }
    std::ifstream in(list);
    std::string rel;
    while(std::getline(in, rel)){
        fs::path p = fs::path(CFG.destdir)/rel;
        std::error_code ec;
        fs::remove(p, ec); // ignora erro
    }
    // tenta limpar diretórios vazios
    std::string clean = "bash -lc 'sort -r \"" + list.string() + "\" | xargs -I{} dirname {} | sort -u | while read d; do rmdir -p --ignore-fail-on-non-empty \"" + CFG.destdir + "/$d\" 2>/dev/null || true; done'";
    runCommand(clean);

    DBSTATE.installed.erase(name);
    db_save();

    runHooks("post-remove", name);
    logInfo("Remoção concluída: " + name);
    return 0;
}

// upgrade = remove + install
static int action_upgrade(const std::string& name){
    int rc = action_remove(name);
    if(rc!=0) return rc;
    return action_install_one(name);
}

static int action_reinstall(const std::string& name){
    return action_install_one(name);
}

// limpa work/log/stage
static int action_clean(const std::string& name){
    runHooks("pre-clean", name);
    std::error_code ec;
    fs::remove_all(workDir(name), ec);
    fs::remove_all(logDir(name), ec);
    fs::remove_all(stageDir(name), ec);
    runHooks("post-clean", name);
    logInfo("Clean concluído: " + name);
    return 0;
}

static int action_info(const std::string& name){
    PackageMeta m;
    if(!loadMetaFile(name, m)) return 1;
    std::cout<<"Nome: "<<m.name<<"\n";
    std::cout<<"Versão: "<<m.version<<"\n";
    std::cout<<"Fonte: "<<m.source_url<<"\n";
    std::cout<<"SHA256: "<<m.sha256<<"\n";
    std::cout<<"Deps:";
    for(size_t i=0;i<m.deps.size();++i){
        std::cout<<(i?", ":" ")<<m.deps[i];
    }
    std::cout<<"\n";
    fs::path fl = filesPath(name);
    if(fileExists(fl)) std::cout<<"Arquivos (.files): "<<fl.string()<<"\n";
    return 0;
}

static int action_search(const std::string& term){
    for(auto& e: fs::directory_iterator(CFG.repo)){
        if(!e.is_regular_file()) continue;
        if(e.path().extension()==".meta"){
            std::string nm = e.path().stem().string();
            if(nm.find(term)!=std::string::npos){
                std::cout<<nm<<"\n"; continue;
            }
            PackageMeta m = parseMeta(e.path().string());
            if(m.source_url.find(term)!=std::string::npos) std::cout<<nm<<"\n";
        }
    }
    return 0;
}

static int action_verify(const std::string& file, const std::string& sum){
    std::string got = sha256sum(file);
    if(got.empty()){ logErr("Falha ao ler arquivo"); return 1; }
    if(got==sum){ logInfo("SHA256 OK"); return 0; }
    logErr("SHA256 não confere.\nEsperado: "+sum+"\nObtido:  "+got);
    return 2;
}

// revdep: usa ldd para encontrar "not found"
static int action_revdep(const std::string& name){
    fs::path list = filesPath(name);
    if(!fileExists(list)){ logErr("Sem .files; gere package/instale primeiro."); return 1; }
    std::ifstream in(list);
    std::string rel;
    std::set<std::string> missing;
    while(std::getline(in, rel)){
        fs::path p = fs::path(CFG.destdir)/rel;
        if(!fileExists(p)) continue;
        // checa se é ELF
        std::string type = execCapture("file -b \"" + p.string() + "\"");
        if(type.find("executable")==std::string::npos && type.find("shared object")==std::string::npos) continue;
        std::string out = execCapture("ldd \"" + p.string() + "\" 2>/dev/null | awk '/not found/{print $1}'");
        std::istringstream iss(out);
        std::string lib;
        while(iss>>lib) missing.insert(lib);
    }
    if(missing.empty()){ logInfo("Sem dependências ausentes detectadas."); return 0; }
    logWarn("Bibliotecas ausentes:");
    for(auto& l: missing) std::cout<<"  "<<l<<"\n";

    logInfo("Possíveis pacotes que fornecem libs compatíveis:");
    for(auto& e: fs::directory_iterator(CFG.repo)){
        if(e.path().extension()==".files"){
            std::ifstream f(e.path());
            std::string r; std::set<std::string> libs;
            while(std::getline(f, r)){
                if(r.find(".so")!=std::string::npos) libs.insert(fs::path(r).filename().string());
            }
            for(auto& miss: missing){
                for(auto& have: libs){
                    if(have.rfind(miss,0)==0){
                        std::cout<<"  - "<<e.path().stem().string()<<" (tem "<<have<<")\n";
                    }
                }
            }
        }
    }
    return 0;
}

// sync (git) — commit/push de diretórios configurados
static int action_sync(const std::string& scope, const std::optional<std::string>& message,
                       const std::optional<std::string>& remoteOpt, const std::optional<std::string>& branchOpt,
                       bool push, bool init_repo)
{
    fs::path root = CFG.home;
    ensureDir(root);

    if(init_repo){
        if(!fileExists(root/".git")){
            if(!runCommand("git -C '"+root.string()+"' init")){ logErr("git init falhou"); return 1; }
        }
        if(remoteOpt && !remoteOpt->empty()){
            runCommand("git -C '"+root.string()+"' remote remove origin >/dev/null 2>&1 || true");
            if(!runCommand("git -C '"+root.string()+"' remote add origin '"+*remoteOpt+"'")){ logErr("git remote add falhou"); return 1; }
        } else if(!CFG.git_remote.empty()){
            runCommand("git -C '"+root.string()+"' remote remove origin >/dev/null 2>&1 || true");
            runCommand("git -C '"+root.string()+"' remote add origin '"+CFG.git_remote+"'");
        }
    }

    if(!fileExists(root/".gitignore")){
        std::ofstream gi(root/".gitignore");
        gi << "# pkgmgr defaults\n*.tmp\n.cache/\n";
    }

    std::vector<fs::path> paths;
    if(scope=="all"){ paths = {CFG.repo, CFG.logs, CFG.work, CFG.sources, CFG.bin, CFG.staging}; }
    else if(scope=="repo"){ paths = {CFG.repo}; }
    else if(scope=="logs"){ paths = {CFG.logs}; }
    else if(scope=="packages"||scope=="pkgs"){ paths = {CFG.repo}; }
    else if(scope=="work"){ paths = {CFG.work}; }
    else if(scope=="sources"){ paths = {CFG.sources}; }
    else { logWarn("Escopo desconhecido: "+scope+" — usando 'repo'"); paths = {CFG.repo}; }

    for(const auto& p: paths){
        if(!fileExists(p)) continue;
        runCommand("git -C '"+root.string()+"' add -A '"+fs::relative(p, root).string()+"'");
    }

    std::string msg = message.value_or(("pkgmgr sync: " + now_ts("%Y-%m-%d %H:%M:%S")));
    runCommand("bash -lc \"cd '"+root.string()+"' && git diff --cached --quiet || git commit -m '"+msg+"'\"");

    std::string remote = remoteOpt.value_or(CFG.git_remote);
    std::string branch = branchOpt.value_or(CFG.git_branch);
    if(push){
        if(remote.empty()){ logWarn("Remote não definido"); return 0; }
        runCommand("bash -lc \"cd '"+root.string()+"' && git symbolic-ref -q HEAD || git checkout -b '"+branch+"'\"");
        if(!runCommand("git -C '"+root.string()+"' push -u '"+remote+"' '"+branch+"'")){ logErr("git push falhou"); return 1; }
        logInfo("Push realizado: " + remote + " " + branch);
    }
    return 0;
}

// instala com resolução de dependências
static int action_install(const std::string& name){
    // 1) carregar metas envolvidos
    auto metas = collectMetas(name);
    if(metas.count(name)==0){ logErr("Receita/metadata não encontrada para '"+name+"' em "+CFG.repo); return 1; }

    // 2) ordenar topologicamente
    auto order = topoSort(metas, name);
    if(order.empty()) order.push_back(name); // fallback
    logInfo("Ordem de instalação:");
    for(auto& p: order) std::cerr<<" -> "<<p; std::cerr<<"\n";

    // 3) para cada pacote: fetch (se source), extract, build, test, stage, package e instalar
    for(const auto& p: order){
        const auto& m = metas[p];

        // fetch se URL/git referida em metadata
        if(!m.source_url.empty()){
            // nome do artefato
            std::optional<std::string> sha;
            if(!m.sha256.empty()) sha = m.sha256;
            int frc = action_fetch(m.source_url, p, sha);
            if(frc!=0) return frc;

            // se baixou um arquivo (não git), tenta extrair para work
            fs::path src = fs::path(CFG.sources) / (p);
            // heurística: se é arquivo, extrai; se diretório, copia já foi feito.
            if(fileExists(src) && fs::is_regular_file(src)){
                if(action_extract(src.string(), p)!=0) return 1;
            } else if(fileExists(src) && fs::is_directory(src)){
                // copiar para work se work vazio
                fs::path out = workDir(p);
                if(!fileExists(out) || fs::is_empty(out)){
                    ensureDir(out);
                    runCommand("cp -a '"+src.string()+"'/* '"+out.string()+"/'");
                }
            }
        }

        // build+install esse pacote
        int rc = action_install_one(p);
        if(rc!=0) return rc;
    }
    return 0;
}

// ========================= Ajuda/uso =========================
static void usage(){
    std::cout <<
"mbuild — ferramenta de build/empacote para LFS (com resolução de dependências)\n\n"
"Uso:\n"
"  mbuild <comando> [opções]\n\n"
"Comandos (nomes longos | atalho | número):\n"
"  help                    | h   | 0   — mostrar ajuda\n"
"  fetch <SRC>             | f   | 1   — baixar (curl/git/dir) [--name N] [--sha256 SUM]\n"
"  extract <ARQ|DIR>       | x   | 2   — extrair/copiar para work [--name N]\n"
"  build <NAME>            | b   | 3   — compilar [--jobs N]\n"
"  test <NAME>             | t   | 4   — rodar testes\n"
"  install <NAME>          | i   | 5   — resolver deps e instalar (staging→pacote→sistema)\n"
"      [--destdir D] [--fakeroot] [--strip|--no-strip] [--strip-flags F] [--format zst|xz]\n"
"  package <NAME>          | p   | 6   — gerar pacote a partir do staging [--format zst|xz]\n"
"  remove <NAME>           | rm  | 7   — remover (dependentes → alvo) em ordem reversa\n"
"  upgrade <NAME>          | up  | 8   — remove + install (com deps)\n"
"  reinstall <NAME>        | ri  | 9   — install novamente (com deps)\n"
"  clean <NAME>            | c   | 10  — limpar work/logs/staging do pacote\n"
"  info <NAME>             |     | 11  — exibir metadados do pacote\n"
"  search <TERMO>          | s   | 12  — buscar no repositório local\n"
"  verify <ARQ> --sha256 S | v   | 13  — verificar sha256\n"
"  revdep <NAME>           |     | 14  — checar dependências ausentes (ldd)\n"
"  sync [escopo]           |     | 15  — sincronizar com git (commit/push)\n"
"      escopo: repo|logs|packages|work|sources|all (default: repo)\n"
"      opções: --message MSG --remote URL --branch BR --push|--no-push --init\n"
"\n"
"Flags globais (antes/depois do comando): --color | --no-color | --no-spinner | --quiet | --verbose\n"
"Dirs ativos:\n"
"  home="<<CFG.home<<"\n"
"  sources="<<CFG.sources<<"  work="<<CFG.work<<"  logs="<<CFG.logs<<"\n"
"  repo="<<CFG.repo<<"  bin="<<CFG.bin<<"  staging="<<CFG.staging<<"\n"
"Config: destdir="<<CFG.destdir<<"  jobs="<<CFG.jobs<<"  strip_flags="<<CFG.strip_flags<<"  format="<<CFG.package_format<<"\n"
"Git: remote="<<(CFG.git_remote.empty()?"<none>":CFG.git_remote)<<"  branch="<<CFG.git_branch<<"\n";
}

// ========================= Parser CLI =========================
static std::string mapAlias(const std::string& cmd){
    static const std::map<std::string,std::string> M = {
        {"0","help"}, {"h","help"}, {"help","help"},
        {"1","fetch"}, {"f","fetch"}, {"fetch","fetch"},
        {"2","extract"}, {"x","extract"}, {"extract","extract"},
        {"3","build"}, {"b","build"}, {"build","build"},
        {"4","test"}, {"t","test"}, {"test","test"},
        {"5","install"}, {"i","install"}, {"install","install"},
        {"6","package"}, {"p","package"}, {"package","package"},
        {"7","remove"}, {"rm","remove"}, {"remove","remove"},
        {"8","upgrade"}, {"up","upgrade"}, {"upgrade","upgrade"},
        {"9","reinstall"}, {"ri","reinstall"}, {"reinstall","reinstall"},
        {"10","clean"}, {"c","clean"}, {"clean","clean"},
        {"11","info"}, {"info","info"},
        {"12","search"}, {"s","search"}, {"search","search"},
        {"13","verify"}, {"v","verify"}, {"verify","verify"},
        {"14","revdep"}, {"revdep","revdep"},
        {"15","sync"}, {"sync","sync"}
    };
    auto it=M.find(cmd);
    return it==M.end()? cmd : it->second;
}

// ========================= Main =========================
int main(int argc, char** argv){
    // prepara diretórios base
    ensureDir(CFG.home);
    ensureDir(CFG.sources);
    ensureDir(CFG.work);
    ensureDir(CFG.logs);
    ensureDir(CFG.repo);
    ensureDir(CFG.bin);
    ensureDir(CFG.staging);

    db_load();

    std::vector<std::string> args(argv+1, argv+argc);
    if(args.empty()){ usage(); return 0; }

    // flags globais (aceitas em qualquer posição)
    auto eatFlag = [&](const std::string& f){
        auto it = std::find(args.begin(), args.end(), f);
        if(it!=args.end()){ args.erase(it); return true; } return false;
    };
    auto getOpt = [&](const std::string& key)->std::optional<std::string>{
        for(size_t i=0;i+1<args.size();++i){
            if(args[i]==key){
                auto v=args[i+1];
                args.erase(args.begin()+i, args.begin()+i+2);
                return v;
            }
        }
        return std::nullopt;
    };

    // aplica globais relevantes
    if(eatFlag("--no-strip")) G_DO_STRIP=false;
    if(eatFlag("--strip"))    G_DO_STRIP=true;
    if(eatFlag("--fakeroot")) G_USE_FAKEROOT=true;
    if(auto f=getOpt("--strip-flags")) CFG.strip_flags=*f;
    if(auto d=getOpt("--destdir"))     CFG.destdir=*d;
    if(auto fmt=getOpt("--format"))    CFG.package_format=((*fmt=="zst")?"zst":"xz");
    if(auto j=getOpt("--jobs"))        { try{ CFG.jobs = std::max(1, std::stoi(*j)); }catch(...){ } }

    if(args.empty()){ usage(); return 0; }
    std::string cmd = mapAlias(args.front()); args.erase(args.begin());

    if(cmd=="help"){ usage(); return 0; }

    if(cmd=="fetch"){
        if(args.empty()){ logErr("Uso: fetch <src> [--name N] [--sha256 SUM]"); return 2; }
        std::string src = args.front(); args.erase(args.begin());
        auto name = getOpt("--name");
        auto sha  = getOpt("--sha256");
        return action_fetch(src, name, sha);
    }
    if(cmd=="extract"){
        if(args.empty()){ logErr("Uso: extract <arquivo|dir> [--name N]"); return 2; }
        std::string in = args.front(); args.erase(args.begin());
        auto name = getOpt("--name");
        return action_extract(in, name);
    }
    if(cmd=="build"){
        if(args.empty()){ logErr("Uso: build <name> [--jobs N]"); return 2; }
        std::string name = args.front(); args.erase(args.begin());
        if(auto j=getOpt("--jobs")){ try{ CFG.jobs = std::max(1, std::stoi(*j)); }catch(...){ } }
        return action_build(name);
    }
    if(cmd=="test"){
        if(args.empty()){ logErr("Uso: test <name>"); return 2; }
        return action_test(args.front());
    }
    if(cmd=="install"){
        if(args.empty()){ logErr("Uso: install <name> [--destdir D] [--fakeroot] [--strip|--no-strip] [--strip-flags F] [--format zst|xz]"); return 2; }
        std::string name = args.front(); args.erase(args.begin());
        // flags já capturadas globalmente
        return action_install(name);
    }
    if(cmd=="package"){
        if(args.empty()){ logErr("Uso: package <name> [--format zst|xz]"); return 2; }
        std::string name = args.front(); args.erase(args.begin());
        return action_package(name);
    }
    if(cmd=="remove"){
        if(args.empty()){ logErr("Uso: remove <name>"); return 2; }
        return action_remove(args.front());
    }
    if(cmd=="upgrade"){
        if(args.empty()){ logErr("Uso: upgrade <name>"); return 2; }
        return action_upgrade(args.front());
    }
    if(cmd=="reinstall"){
        if(args.empty()){ logErr("Uso: reinstall <name>"); return 2; }
        return action_reinstall(args.front());
    }
    if(cmd=="clean"){
        if(args.empty()){ logErr("Uso: clean <name>"); return 2; }
        return action_clean(args.front());
    }
    if(cmd=="info"){
        if(args.empty()){ logErr("Uso: info <name>"); return 2; }
        return action_info(args.front());
    }
    if(cmd=="search"){
        if(args.empty()){ logErr("Uso: search <termo>"); return 2; }
        return action_search(args.front());
    }
    if(cmd=="verify"){
        if(args.size()<2){ logErr("Uso: verify <arquivo> --sha256 SUM"); return 2; }
        std::string file = args.front(); args.erase(args.begin());
        auto sum = getOpt("--sha256");
        if(!sum){ logErr("--sha256 obrigatório"); return 2; }
        return action_verify(file, *sum);
    }
    if(cmd=="revdep"){
        if(args.empty()){ logErr("Uso: revdep <name>"); return 2; }
        return action_revdep(args.front());
    }
    if(cmd=="sync"){
        std::string scope = "repo";
        if(!args.empty() && args.front().rfind("-",0)!=0){ scope = args.front(); args.erase(args.begin()); }
        auto msg = getOpt("--message");
        auto rem = getOpt("--remote");
        auto br  = getOpt("--branch");
        bool push = true;
        if(eatFlag("--no-push")) push=false;
        if(eatFlag("--push")) push=true;
        bool init_repo = eatFlag("--init");
        return action_sync(scope, msg, rem, br, push, init_repo);
    }

    logErr("Comando desconhecido: " + cmd);
    usage();
    return 2;
}
