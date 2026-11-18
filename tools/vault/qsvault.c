/**
 * @file qsvault.c
 * @brief qsvault command-line tool: encrypt and decrypt files with the layered scheme in qsv_core.
 *
 *   qsvault keygen-ckey  <out.qs.ckey>
 *   qsvault keygen-sign  <basename> --ckey K [--usb U] [--iter N]
 *   qsvault encrypt      <in> <out.qsv> --ckey K [--usb U] [--sign BASE] [--iter N]
 *   qsvault decrypt      <in.qsv> <out> --ckey K [--usb U] [--trust BASE]
 *   qsvault info         <in.qsv>
 *
 * keygen-sign writes BASE.pk (public key, plain) and BASE.sk.qsv (secret key sealed with the
 * same password, .qs.ckey and optional USB key). So the signing key is protected by the same
 * layers as the data.
 *
 * Password: prompted without echo on Windows. QSV_PASSWORD in the environment works for scripts,
 * but environment variables can be read by other processes, so prefer the prompt.
 */
#include "qsv_core.h"
#include "qsv_cloud.h"
#include "qsv_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <conio.h>
#endif

#define PK_BYTES 1952u
#define SK_BYTES 4032u

/* ---- file helpers ------------------------------------------------------------ */

static int read_file(const char* path, uint8_t** buf, size_t* len) {
    FILE* f;
    long n;
    *buf = NULL;
    *len = 0;
    f = fopen(path, "rb");
    if (!f) return 0;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    n = ftell(f);
    if (n < 0) { fclose(f); return 0; }
    rewind(f);
    *buf = (uint8_t*)malloc(n > 0 ? (size_t)n : 1u);
    if (!*buf) { fclose(f); return 0; }
    if (n > 0 && fread(*buf, 1, (size_t)n, f) != (size_t)n) {
        free(*buf);
        *buf = NULL;
        fclose(f);
        return 0;
    }
    fclose(f);
    *len = (size_t)n;
    return 1;
}

static int write_file(const char* path, const uint8_t* buf, size_t len) {
    FILE* f = fopen(path, "wb");
    if (!f) return 0;
    if (len && fwrite(buf, 1, len, f) != len) { fclose(f); return 0; }
    return fclose(f) == 0;
}

/* Reads a line without echo where the platform allows it. Returns length, or -1 on error. */
static int read_line_noecho(const char* prompt, char* buf, size_t cap) {
    size_t n = 0;
    fprintf(stderr, "%s", prompt);
    fflush(stderr);
#ifdef _WIN32
    for (;;) {
        int c = _getch();
        if (c == '\r' || c == '\n') break;
        if (c == '\b') {
            if (n > 0) { n--; fputs("\b \b", stderr); }
            continue;
        }
        if (c == 0 || c == 0xE0) { (void)_getch(); continue; }
        if (n + 1 < cap) { buf[n++] = (char)c; fputc('*', stderr); }
    }
    fputc('\n', stderr);
#else
    fprintf(stderr, "(warning: echo is not disabled on this platform)\n");
    if (!fgets(buf, (int)cap, stdin)) return -1;
    n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) n--;
#endif
    buf[n] = '\0';
    return (int)n;
}

/* Fills buf with the password. confirm=1 asks twice (used when creating a vault). */
static int get_password(int confirm, char* buf, size_t cap) {
    const char* env = getenv("QSV_PASSWORD");
    if (env && *env) {
        fprintf(stderr, "(using QSV_PASSWORD from the environment)\n");
        strncpy(buf, env, cap - 1);
        buf[cap - 1] = '\0';
        return (int)strlen(buf);
    }
    if (read_line_noecho("Password: ", buf, cap) < 0) return -1;
    if (confirm) {
        char again[256];
        int ok;
        if (read_line_noecho("Confirm password: ", again, sizeof again) < 0) {
            qsc_secure_zero(again, sizeof again);
            return -1;
        }
        ok = (strcmp(buf, again) == 0);
        qsc_secure_zero(again, sizeof again);
        if (!ok) { fprintf(stderr, "passwords do not match\n"); return -1; }
    }
    return (int)strlen(buf);
}

static int load_keyfile(const char* path, uint8_t secret[32]) {
    uint8_t* buf;
    size_t len;
    int ok = 0;
    if (!read_file(path, &buf, &len)) { fprintf(stderr, "cannot read key file: %s\n", path); return 0; }
    if (qsv_keyfile_parse(buf, len, secret) == QSC_OK) ok = 1;
    else fprintf(stderr, "not a valid .qs.ckey file: %s\n", path);
    qsv_free(buf, len);
    return ok;
}

static int load_pubkey(const char* base, uint8_t pk[PK_BYTES]) {
    char path[512];
    uint8_t* buf;
    size_t len;
    int ok = 0;
    snprintf(path, sizeof path, "%s.pk", base);
    if (!read_file(path, &buf, &len)) { fprintf(stderr, "cannot read public key: %s\n", path); return 0; }
    if (len == PK_BYTES) { memcpy(pk, buf, PK_BYTES); ok = 1; }
    else fprintf(stderr, "public key has the wrong size: %s\n", path);
    qsv_free(buf, len);
    return ok;
}

/* ---- messages ---------------------------------------------------------------- */

static void print_error(const char* what, qsc_error_t e) {
    switch (e) {
    case QSC_ERROR_AUTH_FAILED:
        fprintf(stderr, "%s failed: wrong password, or the file was modified\n", what); break;
    case QSC_ERROR_INVALID_KEY:
        fprintf(stderr, "%s failed: this key file or USB key does not belong to this vault\n", what); break;
    case QSC_ERROR_INVALID_SIGNATURE:
        fprintf(stderr, "%s failed: signature check failed (wrong signer, or the file was modified)\n", what); break;
    case QSC_ERROR_WEAK_KEY:
        fprintf(stderr, "%s failed: password must be at least %u characters\n", what, (unsigned)QSV_MIN_PASSWORD); break;
    case QSC_ERROR_UNSUPPORTED:
        fprintf(stderr, "%s failed: the cloud layer is unavailable. Either this build has it off, "
                        "or QSV_CLOUD_URL is not set or the server is unreachable.\n", what); break;
    case QSC_ERROR_MALFORMED_DATA:
    case QSC_ERROR_TRUNCATED:
        fprintf(stderr, "%s failed: not a valid qsvault file, or it is damaged\n", what); break;
    case QSC_ERROR_INVALID_ARGUMENT:
        fprintf(stderr, "%s failed: missing or inconsistent options (a signed file needs --trust BASE)\n", what); break;
    default:
        fprintf(stderr, "%s failed: error code %d\n", what, (int)e); break;
    }
}

static void usage(void) {
    fprintf(stderr,
        "qsenc: encrypt and decrypt files with layered keys\n"
        "\n"
        "COMMANDS\n"
        "  qsenc keygen-ckey <out.qs.ckey>\n"
        "      Create a key file. Every vault needs one. Keep it safe: losing it\n"
        "      makes every file that uses it unrecoverable.\n"
        "\n"
        "  qsenc keygen-sign <basename> --ckey K [--usb U]\n"
        "      Create a signing identity. Writes <basename>.pk (public, share it)\n"
        "      and <basename>.sk.qsv (secret key, sealed with your password and keys).\n"
        "\n"
        "  qsenc encrypt <in> <out.qsv> --ckey K [--usb U] [--sign BASE]\n"
        "  qsenc decrypt <in.qsv> <out> --ckey K [--usb U] [--trust BASE]\n"
        "  qsenc info <in.qsv>          (shows which layers a file uses; needs no keys)\n"
        "\n"
        "LAYERS\n"
        "  password     Always required. You are prompted (at least 12 characters).\n"
        "  --ckey K     Always required. K is a .qs.ckey key file.\n"
        "  --usb U      Optional. U is a key file kept on a USB drive. Create it with\n"
        "               'qsenc keygen-ckey E:\\usb.qs.ckey'. The file cannot be decrypted\n"
        "               without that drive plugged in.\n"
        "  --sign BASE  Optional (encrypt only). Signs the file with the identity BASE,\n"
        "               which must have been created with keygen-sign.\n"
        "  --trust BASE Required to decrypt a signed file. Checks the signature against\n"
        "               BASE.pk. Without it, decryption refuses the file.\n"
        "  cloud        Not a command-line option. It is a build-time switch and is OFF\n"
        "               in this build. See tools/vault/CLOUD_SETUP.md to enable it.\n"
        "               A file that needs cloud validation cannot be decrypted while off.\n"
        "\n"
        "OPTIONS\n"
        "  --iter N     Key-derivation rounds (default 600000). Stored in the file.\n"
        "\n"
        "ENVIRONMENT\n"
        "  QSV_PASSWORD  Password for scripts. Less safe than the prompt, because other\n"
        "                processes can read environment variables.\n"
        "\n"
        "EXAMPLES\n"
        "  qsenc keygen-ckey home.qs.ckey\n"
        "  qsenc keygen-ckey E:\\usb.qs.ckey\n"
        "  qsenc encrypt notes.txt notes.qsv --ckey home.qs.ckey --usb E:\\usb.qs.ckey\n"
        "  qsenc decrypt notes.qsv notes.txt --ckey home.qs.ckey --usb E:\\usb.qs.ckey\n");
#if QSV_CLOUD_ENABLED
    fprintf(stderr,
        "\n"
        "CLOUD (this build only). Needs QSV_CLOUD_URL. Restoring needs the password and the cloud key.\n"
        "  qsenc keygen-cloud <dir>                          create key-<id>.cloud.ckey.qs in <dir>\n"
        "  qsenc cloud-backup <file.qs.ckey> --cloud-key K     upload encrypted, then delete the local file\n"
        "  qsenc keygen-ckey --cloud --cloud-key K            make a key straight into the cloud (no local file)\n"
        "  qsenc cloud-restore <out.qs.ckey> --cloud-key K     download and decrypt a backup\n");
#endif
}

/* ---- option parsing ---------------------------------------------------------- */

typedef struct {
    const char* pos[2];
    int npos;
    const char* ckey;
    const char* usb;
    const char* sign;
    const char* trust;
    unsigned long iter;
    int cloud;
    const char* cloud_key;
} args_t;

static int parse_args(int argc, char** argv, args_t* a) {
    int i;
    memset(a, 0, sizeof *a);
    for (i = 2; i < argc; i++) {
        const char* s = argv[i];
        if (strcmp(s, "--ckey") == 0 && i + 1 < argc) a->ckey = argv[++i];
        else if (strcmp(s, "--usb") == 0 && i + 1 < argc) a->usb = argv[++i];
        else if (strcmp(s, "--sign") == 0 && i + 1 < argc) a->sign = argv[++i];
        else if (strcmp(s, "--trust") == 0 && i + 1 < argc) a->trust = argv[++i];
        else if (strcmp(s, "--iter") == 0 && i + 1 < argc) a->iter = strtoul(argv[++i], NULL, 10);
        else if (strcmp(s, "--cloud") == 0) a->cloud = 1;
        else if (strcmp(s, "--cloud-key") == 0 && i + 1 < argc) a->cloud_key = argv[++i];
        else if (s[0] == '-' && s[1] == '-') { fprintf(stderr, "unknown or incomplete option: %s\n", s); return 0; }
        else {
            if (a->npos >= 2) { fprintf(stderr, "too many arguments\n"); return 0; }
            a->pos[a->npos++] = s;
        }
    }
    return 1;
}

/* Loads the key-file secrets named on the command line. */
static int load_factors(const args_t* a, uint8_t ckey[32], uint8_t usb[32], int* have_usb) {
    if (!a->ckey) { fprintf(stderr, "--ckey is required\n"); return 0; }
    if (!load_keyfile(a->ckey, ckey)) return 0;
    *have_usb = 0;
    if (a->usb) {
        if (!load_keyfile(a->usb, usb)) return 0;
        *have_usb = 1;
    }
    return 1;
}

/* ---- commands ---------------------------------------------------------------- */

static int cmd_keygen_ckey(const args_t* a) {
    uint8_t kf[QSV_KEYFILE_BYTES];
    if (a->npos != 1) { usage(); return 2; }
    if (qsv_keyfile_make(kf) != QSC_OK) { fprintf(stderr, "random generation failed\n"); return 1; }
    if (!write_file(a->pos[0], kf, sizeof kf)) { fprintf(stderr, "cannot write %s\n", a->pos[0]); return 1; }
    qsc_secure_zero(kf, sizeof kf);
    fprintf(stderr, "wrote %s. Keep it safe: losing it makes every vault that uses it unrecoverable.\n", a->pos[0]);
    return 0;
}

static int cmd_keygen_sign(const args_t* a) {
    uint8_t ckey[32], usb[32], pk[PK_BYTES], sk[SK_BYTES];
    char pw[256], path[512];
    int have_usb = 0, rc = 1;
    qsv_secrets_t s;
    uint8_t* sealed = NULL;
    size_t sealed_len = 0;
    qsc_error_t e;

    if (a->npos != 1) { usage(); return 2; }
    if (!load_factors(a, ckey, usb, &have_usb)) return 1;
    if (get_password(1, pw, sizeof pw) < 0) { fprintf(stderr, "no password\n"); goto out; }

    e = qsc_mldsa65_keygen(pk, sk);
    if (e != QSC_OK) { print_error("key generation", e); goto out; }

    memset(&s, 0, sizeof s);
    s.password = (const uint8_t*)pw;
    s.password_len = strlen(pw);
    s.ckey = ckey;
    s.usb = have_usb ? usb : NULL;
    s.iterations = (uint32_t)a->iter;
    e = qsv_encrypt(&s, sk, SK_BYTES, &sealed, &sealed_len);
    if (e != QSC_OK) { print_error("sealing the signing key", e); goto out; }

    snprintf(path, sizeof path, "%s.pk", a->pos[0]);
    if (!write_file(path, pk, PK_BYTES)) { fprintf(stderr, "cannot write %s\n", path); goto out; }
    snprintf(path, sizeof path, "%s.sk.qsv", a->pos[0]);
    if (!write_file(path, sealed, sealed_len)) { fprintf(stderr, "cannot write %s\n", path); goto out; }

    fprintf(stderr, "wrote %s.pk (public, share freely) and %s.sk.qsv (sealed secret key)\n",
            a->pos[0], a->pos[0]);
    rc = 0;

out:
    qsc_secure_zero(pw, sizeof pw);
    qsc_secure_zero(sk, sizeof sk);
    qsc_secure_zero(ckey, sizeof ckey);
    qsc_secure_zero(usb, sizeof usb);
    if (sealed) qsv_free(sealed, sealed_len);
    return rc;
}

static int cmd_encrypt(const args_t* a) {
    uint8_t ckey[32], usb[32], pk[PK_BYTES], *sk = NULL, *in = NULL, *out = NULL;
    size_t sk_len = 0, in_len = 0, out_len = 0;
    char pw[256], path[512];
    int have_usb = 0, rc = 1;
    qsv_secrets_t s;
    qsc_error_t e;

    if (a->npos != 2) { usage(); return 2; }
    if (!load_factors(a, ckey, usb, &have_usb)) return 1;
    if (!read_file(a->pos[0], &in, &in_len)) { fprintf(stderr, "cannot read %s\n", a->pos[0]); goto out; }
    if (get_password(1, pw, sizeof pw) < 0) { fprintf(stderr, "no password\n"); goto out; }

    memset(&s, 0, sizeof s);
    s.password = (const uint8_t*)pw;
    s.password_len = strlen(pw);
    s.ckey = ckey;
    s.usb = have_usb ? usb : NULL;
    s.iterations = (uint32_t)a->iter;

    if (a->sign) {
        /* Unseal the signing key with the same factors, then sign. */
        uint8_t* sk_file = NULL;
        size_t sk_file_len = 0;
        uint8_t* plain_sk = NULL;
        size_t plain_len = 0;
        snprintf(path, sizeof path, "%s.sk.qsv", a->sign);
        if (!read_file(path, &sk_file, &sk_file_len)) {
            fprintf(stderr, "cannot read %s\n", path);
            goto out;
        }
        e = qsv_decrypt(&s, NULL, sk_file, sk_file_len, &plain_sk, &plain_len);
        qsv_free(sk_file, sk_file_len);
        if (e != QSC_OK) { print_error("unsealing the signing key", e); goto out; }
        if (plain_len != SK_BYTES || !load_pubkey(a->sign, pk)) {
            if (plain_sk) qsv_free(plain_sk, plain_len);
            fprintf(stderr, "signing key is malformed\n");
            goto out;
        }
        sk = plain_sk;
        sk_len = plain_len;
        s.sign_sk = sk;
        s.sign_pk = pk;
    }

    e = qsv_encrypt(&s, in, in_len, &out, &out_len);
    if (e != QSC_OK) { print_error("encryption", e); goto out; }
    if (!write_file(a->pos[1], out, out_len)) { fprintf(stderr, "cannot write %s\n", a->pos[1]); goto out; }
    fprintf(stderr, "encrypted %s -> %s (%lu bytes)\n", a->pos[0], a->pos[1], (unsigned long)out_len);
    rc = 0;

out:
    qsc_secure_zero(pw, sizeof pw);
    qsc_secure_zero(ckey, sizeof ckey);
    qsc_secure_zero(usb, sizeof usb);
    if (sk) qsv_free(sk, sk_len);
    if (in) qsv_free(in, in_len);
    if (out) qsv_free(out, out_len);
    return rc;
}

static int cmd_decrypt(const args_t* a) {
    uint8_t ckey[32], usb[32], trust[PK_BYTES];
    uint8_t *in = NULL, *pt = NULL;
    size_t in_len = 0, pt_len = 0;
    char pw[256];
    int have_usb = 0, rc = 1;
    const uint8_t* trust_ptr = NULL;
    qsv_secrets_t s;
    qsc_error_t e;

    if (a->npos != 2) { usage(); return 2; }
    if (!load_factors(a, ckey, usb, &have_usb)) return 1;
    if (a->trust) {
        if (!load_pubkey(a->trust, trust)) return 1;
        trust_ptr = trust;
    }
    if (!read_file(a->pos[0], &in, &in_len)) { fprintf(stderr, "cannot read %s\n", a->pos[0]); goto out; }
    if (get_password(0, pw, sizeof pw) < 0) { fprintf(stderr, "no password\n"); goto out; }

    memset(&s, 0, sizeof s);
    s.password = (const uint8_t*)pw;
    s.password_len = strlen(pw);
    s.ckey = ckey;
    s.usb = have_usb ? usb : NULL;

    e = qsv_decrypt(&s, trust_ptr, in, in_len, &pt, &pt_len);
    if (e != QSC_OK) { print_error("decryption", e); goto out; }
    if (!write_file(a->pos[1], pt, pt_len)) { fprintf(stderr, "cannot write %s\n", a->pos[1]); goto out; }
    fprintf(stderr, "decrypted %s -> %s (%lu bytes)\n", a->pos[0], a->pos[1], (unsigned long)pt_len);
    rc = 0;

out:
    qsc_secure_zero(pw, sizeof pw);
    qsc_secure_zero(ckey, sizeof ckey);
    qsc_secure_zero(usb, sizeof usb);
    if (in) qsv_free(in, in_len);
    if (pt) qsv_free(pt, pt_len);
    return rc;
}

static int cmd_info(const args_t* a) {
    uint8_t* in = NULL;
    size_t in_len = 0;
    qsv_info_t info;
    int rc = 1;
    if (a->npos != 1) { usage(); return 2; }
    if (!read_file(a->pos[0], &in, &in_len)) { fprintf(stderr, "cannot read %s\n", a->pos[0]); return 1; }
    if (qsv_info(in, in_len, &info) != QSC_OK) {
        fprintf(stderr, "not a valid qsvault file\n");
    } else {
        printf("file:        %s\n", a->pos[0]);
        printf("size:        %lu bytes\n", (unsigned long)info.total_bytes);
        printf("password:    %s\n", (info.flags & QSV_FLAG_PASSWORD) ? "yes" : "no");
        printf("ckey:        %s\n", (info.flags & QSV_FLAG_CKEY) ? "yes" : "no");
        printf("usb key:     %s\n", (info.flags & QSV_FLAG_USB) ? "yes" : "no");
        printf("signed:      %s\n", (info.flags & QSV_FLAG_SIGNED) ? "yes" : "no");
        printf("cloud:       %s\n", (info.flags & QSV_FLAG_CLOUD) ? "yes" : "no");
        printf("kdf rounds:  %lu\n", (unsigned long)info.iterations);
        rc = 0;
    }
    qsv_free(in, in_len);
    return rc;
}

#if QSV_CLOUD_ENABLED
/* Cloud transport through the system curl (built into Windows 10 and later). The JSON body goes
 * through a temporary file so it never appears on a command line. The URL is checked first,
 * because it is placed inside a shell command. */
static qsc_error_t curl_post(const char* url, const char* json_body, char* resp, size_t resp_cap) {
    static const char tmp[] = "qsv_cloud_body.tmp";
    char cmd[1024];
    FILE* f;
    FILE* p;
    size_t n;
    int status;
    const char* c;

    if (strncmp(url, "https://", 8) != 0) return QSC_ERROR_INVALID_ARGUMENT;
    for (c = url; *c; c++) {
        if (*c == '"' || *c == '\'' || *c == '&' || *c == '|' || *c == ';' ||
            *c == '<' || *c == '>' || *c == '`' || *c == '$' || *c == ' ' || *c == '\n' || *c == '\r')
            return QSC_ERROR_INVALID_ARGUMENT;
    }
    f = fopen(tmp, "wb");
    if (!f) return QSC_ERROR_UNSUPPORTED;
    fputs(json_body, f);
    fclose(f);

    snprintf(cmd, sizeof cmd,
             "curl -s -m 20 -X POST -H \"Content-Type: application/json\" --data-binary @%s \"%s\"",
             tmp, url);
#ifdef _WIN32
    p = _popen(cmd, "r");
#else
    p = popen(cmd, "r");
#endif
    if (!p) { remove(tmp); return QSC_ERROR_UNSUPPORTED; }
    n = fread(resp, 1, resp_cap - 1, p);
    resp[n] = '\0';
#ifdef _WIN32
    status = _pclose(p);
#else
    status = pclose(p);
#endif
    remove(tmp);
    /* The reply holds only {"ok":...} or an error code, never key material. */
    if (status != 0) fprintf(stderr, "cloud request failed (curl status %d): %s\n", status, resp);
    return status == 0 ? QSC_OK : QSC_ERROR_UNSUPPORTED;
}
#endif

#if QSV_CLOUD_ENABLED
#include "qsv_cloudstore.h"
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

static char g_cloud_url[512] = "";

static qsc_error_t store_call(const char* path, const char* body, char* resp, size_t cap) {
    char url[640];
    if (!g_cloud_url[0]) return QSC_ERROR_UNSUPPORTED;
    snprintf(url, sizeof url, "%s%s", g_cloud_url, path);
    return curl_post(url, body, resp, cap);
}

static int file_exists(const char* p) {
    FILE* f = fopen(p, "rb");
    if (f) { fclose(f); return 1; }
    return 0;
}

/* Local index: <USERPROFILE>/quantum-suite-org/qs_crypt/cloud-index.txt. Folders are created. */
static int index_path(char* out, size_t cap) {
    const char* base = getenv("USERPROFILE");
    char org[512], dir[512];
    if (!base) base = getenv("HOME");
    if (!base) return 0;
    snprintf(org, sizeof org, "%s/quantum-suite-org", base);
    snprintf(dir, sizeof dir, "%s/quantum-suite-org/qs_crypt", base);
#ifdef _WIN32
    _mkdir(org);
    _mkdir(dir);
#else
    mkdir(org, 0700);
    mkdir(dir, 0700);
#endif
    snprintf(out, cap, "%s/cloud-index.txt", dir);
    return 1;
}

/* Overwrites the file with zeros, then removes it. Overwriting does not guarantee erasure on SSDs,
 * so the real protection is that the only copy left in the cloud is encrypted. */
static void secure_delete(const char* path, size_t len) {
    FILE* f = fopen(path, "r+b");
    uint8_t zeros[256];
    size_t left = len;
    if (f) {
        memset(zeros, 0, sizeof zeros);
        while (left > 0) {
            size_t n = left < sizeof zeros ? left : sizeof zeros;
            fwrite(zeros, 1, n, f);
            left -= n;
        }
        fflush(f);
        fclose(f);
    }
    remove(path);
}

/* Uploads the 40-byte .qs.ckey contents sealed with the password and the cloud key. */
static int cloud_backup_bytes(const uint8_t ckey[QSV_KEYFILE_BYTES], const args_t* a,
                              char created[QSV_CS_TIME_MAX]) {
    uint8_t* ckf = NULL;
    size_t ckfl = 0;
    uint8_t cloud[QSV_CS_CLOUDKEY_BYTES];
    uint8_t secret[32];
    char pw[256];
    char id[QSV_CS_ID_LEN + 1];
    char ipath[512];
    qsc_error_t e;
    int ok = 0;

    if (!a->cloud_key) { fprintf(stderr, "--cloud-key FILE is required\n"); return 0; }
    if (!g_cloud_url[0]) { fprintf(stderr, "QSV_CLOUD_URL is not set\n"); return 0; }
    if (!read_file(a->cloud_key, &ckf, &ckfl)) { fprintf(stderr, "cannot read %s\n", a->cloud_key); return 0; }
    if (ckfl != QSV_CS_CLOUDKEY_BYTES) {
        qsv_free(ckf, ckfl);
        fprintf(stderr, "not a cloud key file: %s\n", a->cloud_key);
        return 0;
    }
    memcpy(cloud, ckf, sizeof cloud);
    qsv_free(ckf, ckfl);
    if (qsv_cs_cloudkey_parse(cloud, sizeof cloud, id, secret) != QSC_OK) {
        fprintf(stderr, "not a cloud key file: %s\n", a->cloud_key);
        goto out;
    }
    if (get_password(1, pw, sizeof pw) < 0) goto out;

    e = qsv_cs_backup(store_call, cloud, sizeof cloud, (const uint8_t*)pw, strlen(pw),
                      ckey, (uint32_t)a->iter, created);
    if (e != QSC_OK) { print_error("cloud backup", e); goto out; }
    if (index_path(ipath, sizeof ipath) && qsv_cs_index_write(ipath, id, created) != QSC_OK)
        fprintf(stderr, "warning: could not update the local index\n");
    ok = 1;

out:
    qsc_secure_zero(pw, sizeof pw);
    qsc_secure_zero(cloud, sizeof cloud);
    qsc_secure_zero(secret, sizeof secret);
    return ok;
}

/* keygen-ckey <out> --cloud: make a key, upload it, and keep no local copy. */
static int cmd_keygen_ckey_cloud(const args_t* a) {
    uint8_t kf[QSV_KEYFILE_BYTES];
    char created[QSV_CS_TIME_MAX];
    int ok;
    if (a->npos != 0) { usage(); return 2; }
    if (qsv_keyfile_make(kf) != QSC_OK) { fprintf(stderr, "random generation failed\n"); return 1; }
    ok = cloud_backup_bytes(kf, a, created);
    qsc_secure_zero(kf, sizeof kf);
    if (!ok) return 1;
    printf("created a key and backed it up to the cloud (%s). No local copy was kept.\n", created);
    return 0;
}

/* keygen-cloud <dir>: writes key-<hash>.cloud.ckey.qs into dir. Keep it on a USB drive. */
static int cmd_keygen_cloud(const args_t* a) {
    uint8_t ck[QSV_CS_CLOUDKEY_BYTES];
    char id[QSV_CS_ID_LEN + 1];
    uint8_t secret[32];
    char path[700];
    int rc = 1;
    if (a->npos != 1) { usage(); return 2; }
    if (qsv_cs_cloudkey_make(ck) != QSC_OK) { fprintf(stderr, "random generation failed\n"); return 1; }
    if (qsv_cs_cloudkey_parse(ck, sizeof ck, id, secret) != QSC_OK) { fprintf(stderr, "internal error\n"); goto out; }
    snprintf(path, sizeof path, "%s/%s.cloud.ckey.qs", a->pos[0], id);
    if (file_exists(path)) { fprintf(stderr, "refusing to overwrite %s\n", path); goto out; }
    if (!write_file(path, ck, sizeof ck)) { fprintf(stderr, "cannot write %s\n", path); goto out; }
    printf("wrote %s\nKeep it on a USB drive. Without it, the cloud backups cannot be restored.\n", path);
    rc = 0;
out:
    qsc_secure_zero(ck, sizeof ck);
    qsc_secure_zero(secret, sizeof secret);
    return rc;
}

/* cloud-backup <file.qs.ckey> --cloud-key K: upload an existing key, then delete the local copy. */
static int cmd_cloud_backup(const args_t* a) {
    uint8_t* kf = NULL;
    size_t kfl = 0;
    uint8_t tmp[32];
    char created[QSV_CS_TIME_MAX];
    int rc = 1;
    if (a->npos != 1) { usage(); return 2; }
    if (!read_file(a->pos[0], &kf, &kfl)) { fprintf(stderr, "cannot read %s\n", a->pos[0]); return 1; }
    if (kfl != QSV_KEYFILE_BYTES || qsv_keyfile_parse(kf, kfl, tmp) != QSC_OK) {
        qsv_free(kf, kfl);
        fprintf(stderr, "not a .qs.ckey file: %s\n", a->pos[0]);
        return 1;
    }
    qsc_secure_zero(tmp, sizeof tmp);
    if (cloud_backup_bytes(kf, a, created)) {
        secure_delete(a->pos[0], kfl);
        printf("backed up to the cloud (%s). The local copy was removed.\n", created);
        rc = 0;
    }
    qsv_free(kf, kfl);
    return rc;
}

/* cloud-restore <out.qs.ckey> --cloud-key K: fetch, check the local index, decrypt, write. */
static int cmd_cloud_restore(const args_t* a) {
    uint8_t* ck = NULL;
    size_t ckl = 0;
    uint8_t cloud[QSV_CS_CLOUDKEY_BYTES];
    uint8_t secret[32];
    uint8_t ckey[QSV_KEYFILE_BYTES];
    char pw[256];
    char id[QSV_CS_ID_LEN + 1];
    char created[QSV_CS_TIME_MAX];
    char ipath[512];
    qsc_error_t e;
    int rc = 1;

    if (a->npos != 1) { usage(); return 2; }
    if (!a->cloud_key) { fprintf(stderr, "--cloud-key FILE is required\n"); return 1; }
    if (!g_cloud_url[0]) { fprintf(stderr, "QSV_CLOUD_URL is not set\n"); return 1; }
    if (!read_file(a->cloud_key, &ck, &ckl) || ckl != QSV_CS_CLOUDKEY_BYTES) {
        if (ck) qsv_free(ck, ckl);
        fprintf(stderr, "not a cloud key file: %s\n", a->cloud_key);
        return 1;
    }
    memcpy(cloud, ck, sizeof cloud);
    qsv_free(ck, ckl);
    if (qsv_cs_cloudkey_parse(cloud, sizeof cloud, id, secret) != QSC_OK) {
        fprintf(stderr, "not a cloud key file: %s\n", a->cloud_key);
        goto out;
    }
    if (file_exists(a->pos[0])) { fprintf(stderr, "refusing to overwrite %s\n", a->pos[0]); goto out; }
    if (get_password(0, pw, sizeof pw) < 0) goto out;

    e = qsv_cs_restore(store_call, cloud, sizeof cloud, (const uint8_t*)pw, strlen(pw), ckey, created);
    if (e == QSC_ERROR_INVALID_KEY) {
        fprintf(stderr, "no cloud backup exists for this cloud key\n");
        goto out;
    }
    if (e != QSC_OK) { print_error("cloud restore", e); goto out; }

    /* If this machine has a record for the key, the server's timestamp must match it exactly. */
    if (index_path(ipath, sizeof ipath)) {
        int check = qsv_cs_index_check(ipath, id, created);
        if (check == 1) {
            fprintf(stderr, "refusing: the timestamp does not match the local record for this key\n");
            goto out;
        }
        if (check == 0) qsv_cs_index_write(ipath, id, created);
    }
    if (!write_file(a->pos[0], ckey, sizeof ckey)) { fprintf(stderr, "cannot write %s\n", a->pos[0]); goto out; }
    printf("restored %s (backed up %s)\n", a->pos[0], created);
    rc = 0;

out:
    qsc_secure_zero(pw, sizeof pw);
    qsc_secure_zero(cloud, sizeof cloud);
    qsc_secure_zero(secret, sizeof secret);
    qsc_secure_zero(ckey, sizeof ckey);
    return rc;
}
#endif

int main(int argc, char** argv) {
    args_t a;
    if (argc < 2) { usage(); return 2; }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "help") == 0) {
        usage();
        return 0;
    }
    if (!parse_args(argc, argv, &a)) return 2;
    if (qsc_init() != QSC_OK) { fprintf(stderr, "library init failed\n"); return 1; }
#if QSV_CLOUD_ENABLED
    {
        const char* cloud_url = getenv("QSV_CLOUD_URL");
        if (cloud_url && *cloud_url) {
            qsv_cloud_set_transport(curl_post, cloud_url);
            strncpy(g_cloud_url, cloud_url, sizeof g_cloud_url - 1);
        }
    }
    if (strcmp(argv[1], "keygen-cloud") == 0) return cmd_keygen_cloud(&a);
    if (strcmp(argv[1], "cloud-backup") == 0) return cmd_cloud_backup(&a);
    if (strcmp(argv[1], "cloud-restore") == 0) return cmd_cloud_restore(&a);
    if (strcmp(argv[1], "keygen-ckey") == 0 && a.cloud) return cmd_keygen_ckey_cloud(&a);
#else
    /* The public build has no cloud feature: --cloud is refused without saying why. */
    if (a.cloud) { usage(); return 2; }
#endif
    if (strcmp(argv[1], "keygen-ckey") == 0) return cmd_keygen_ckey(&a);
    if (strcmp(argv[1], "keygen-sign") == 0) return cmd_keygen_sign(&a);
    if (strcmp(argv[1], "encrypt") == 0) return cmd_encrypt(&a);
    if (strcmp(argv[1], "decrypt") == 0) return cmd_decrypt(&a);
    if (strcmp(argv[1], "info") == 0) return cmd_info(&a);
    usage();
    return 2;
}
