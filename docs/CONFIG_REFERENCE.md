# Configuration Reference

NothingDNS, [config.example.yaml](../config.example.yaml) içinde dağıtılan
tek bir YAML dosyası ile yapılandırılır. Bu belge her üst seviye bölümün
alanlarını ve davranışını açıklar.

Notlar:

- Hot-reload sütunu, SIGHUP (veya `POST /api/v1/config/reload`) sonrasında
  yeni değerin çalışan sunucuya uygulanıp uygulanmadığını gösterir:
  **evet** = reload uygular; **hayır** = yeniden başlatma gerekir;
  **kısmi** = açıklamadaki kısım uygulanır. Runtime config API'si
  (`PUT /api/v1/config/*`) bazı değerleri ayrıca canlı değiştirir ve
  `<storage.data_dir>/runtime_overrides.json` dosyasına yazar; dosyadaki
  değer sonraki başlangıçta ve her reload'da YAML'ın yerine geçer (override
  kazanır).
- `0 = auto` notu, sıfır verilirse runtime'ın varsayılanı hesapladığı
  anlamına gelir.
- YAML parser anchor/alias ve multiline string'leri **desteklemez** — düz
  YAML kullanın.
- **Hatalı değerler sessizce varsayılana dönmez, yükleme başarısız olur**
  (başlangıçta, SIGHUP reload'da ve `-validate-config` ile):
  - Girintide **tab** karakteri (yalnızca boşluk kullanın; boş/yorum
    satırlarındaki tab sorun değildir).
  - Çift tırnaklı string'de YAML 1.2 dışı kaçış dizisi (ör. `"a\qb"`);
    Windows yolları ve regex'ler için tek tırnak kullanın.
  - Geçersiz boolean: yalnızca `true/false`, `yes/no`, `on/off`, `1/0`
    (büyük/küçük harf duyarsız) kabul edilir; `ture`, `enable` hata verir.
    Boş değer varsayılanı korur.
  - Liste beklenen bölümün mapping/skaler olarak yazılması (ör. `acl:`
    altında `- ` olmadan `name:`) → `expected a list of "- key: value" items`.
  - Sıfır veya negatif süre: `resolution.timeout`,
    `dnssec.signing.signature_validity`, `cookie.secret_rotation`
    (`must be positive`). Süreler Go formatındadır (`300ms`, `30s`, `5m`,
    `168h`); **`d` birimi yoktur** — `7d` değil `168h` yazın.
  - Bilinmeyen ACL `types` değeri (aşağıdaki [ACL tip tablosu](#acl)).
- **IPv6 değerleri**: `::`, `::1`, `fe80::`, `2001:db8::`, `::1/128`,
  `2001:db8::/32`, `::ffff:1.2.3.4` tırnaksız da tek bir adres olarak okunur
  (`- ::`, `bind: ::`, `bind: [::]`). Bilinçli sapma: katı YAML'da `::` ile
  biten düz değer `{"<adres>:": null}` mapping'idir; NothingDNS bir `:`
  ardından gelen `:`'yı asla mapping ayırıcısı saymaz (dolayısıyla `a:: b`
  bir anahtar değil, hatadır). Köşeli parantezle başlayan port'lu biçim
  (`[::]:53`) tırnaksız yazılamaz — `"[::]:53"` yazın. Tutarlılık için IPv6
  değerlerini tırnak içinde yazmak yine de önerilir.

## SIGHUP ile yeniden yükleme (özet)

SIGHUP ve `POST /api/v1/config/reload` aynı yolu (`cmd/nothingdns/reload.go`)
kullanır. Önce tüm yeni bileşenler hazırlanır; doğrulanamayan config,
okunamayan zone dosyası veya ayrıştırılamayan TSIG anahtarı reload'ı iptal
eder ve çalışan durum değişmez.

| SIGHUP ile uygulanır | Yeniden başlatma gerekir |
|---|---|
| `zones` (eklenen/değişen/kaldırılan dosyalar), `views` | dinleyiciler: adres/port/worker'lar, `server.tls.enabled`, `server.quic.*`, `server.xot.*` (sertifika içeriği hariç), `server.http.*` (auth token/kullanıcılar, CORS, DoH/DoWS/ODoH uç noktaları dahil) |
| `upstream` (istemci ve load balancer yeniden kurulur), `resolution.timeout` dahil | `cache.enabled` (cache her zaman kurulur) |
| iteratif resolver yeniden kurulur: `resolution.recursive` (true→false iteratif çözümlemeyi hemen durdurur, false→true başlatır), `root_hints`, `max_depth`, `timeout`, `edns0_buffer_size`, `qname_minimization`, `use_0x20` ve `dnssec.enabled`'a bağlı DO biti; uçuştaki sorgular eski resolver'da tamamlanır | `logging.output`, `logging.query_log`, `logging.query_log_file` |
| `resolution.authoritative_only` (her istekte okunur) | `dnssec.signing.enabled`, `signing.keys`, `signing.signature_validity` (zone imzalayıcıları başlangıçta kurulur) |
| `cache.size`, `default_ttl`, `max_ttl`, `min_ttl`, `negative_ttl`, `prefetch`, `prefetch_threshold`, `serve_stale`, `stale_grace_secs` (çalışan cache'e uygulanır; içerik korunur) | `metrics.*`, `tracing.*`, `odoh.*`, `memory_limit_mb` |
| `logging.level`, `logging.format` | `idna.check_joiner` (etkisiz, kullanımdan kaldırıldı) |
| `idna.enabled`, `use_std3_rules`, `allow_unassigned`, `check_bidi` | |
| `dnssec.enabled`, `trust_anchor`, `ignore_time`, `require_dnssec` (validator yeniden kurulur), `dnssec.signing.nsec3` (her istekte okunur) | |
| `blocklist` (`base_dir` dahil), `rpz`, `geodns`, `dns64`, `acl`, `allow_recursion`, `server.acl_allow_unrestricted_recursion`, rate limiter / RRL | |
| `transfer.also_notify`, `transfer.notify_key` | `storage.*`, `server.http.auth_secret`, `transfer.journal_dir` |
| `transfer.tsig_keys` (`secret`, `allow_update`, `allowed_cidrs` dahil) | `cluster.*` (`forward_updates` hariç; `dns_advertise_addr`, `peers`, `weight`, `cache_sync`, anahtarlar dahil) |
| `slave_zones[].tsig_secret` | `slave_zones` üyeliği (zone, `masters`, `tsig_key_name`), `transfer.allow_list`, `transfer.require_tsig` |
| `cluster.forward_updates`, `shutdown_timeout` (sonraki kapanışta okunur) | TLS sertifika/anahtar/CA dosya **yolları** (`server.tls.*`, `server.quic.*`, `server.xot.*`, `server.http.tls_*`) |
| TLS sertifika/anahtar dosyalarının **içeriği**: DoT, DoQ, XoT (+ `xot.ca_file`), HTTPS API/DoH (config dosyası yüklenemese bile her reload'da yeniden okunur) | `cluster.rpc` TLS sertifikası (Raft RPC) |

Her reload iteratif resolver'ı yeni `resolution.*` ve `dnssec.enabled`
değerleriyle yeniden kurar ve tek adımda değiştirir; cache içeriği
korunur, yalnızca ayarları güncellenir; logger seviyesi/formatı ve IDNA
ayarları da uygulanır. `PUT /api/v1/config/cache` ve
`PUT /api/v1/config/logging` değerleri hemen canlı değiştirir;
`PUT /api/v1/config/resolution` `authoritative_only`'yi hemen, diğer
resolver alanlarını sonraki reload'da (SIGHUP veya
`POST /api/v1/config/reload`) ya da yeniden başlatmada uygular.
`runtime_overrides.json` ve `access_policy.json` her reload'da YAML'ın
üzerine yeniden uygulanır (onlar kazanır).
Sertifika yenilemesinden sonra (ör. certbot deploy hook'u) SIGHUP
gönderin: her TLS dinleyicisi (DoT, DoQ, XoT, HTTPS API) sertifika ve
anahtarı yeniden okur; SNI'lı ve SNI'sız tüm yeni el sıkışmalar yeni
sertifikayı alır, açık bağlantılar eskisini korur. Yüklenemeyen dosya (eksik
dosya, uyumsuz anahtar, geçersiz CA) o dinleyicide eski sertifikayı/CA'yı
bırakır ve hata loglanır; dinleyici kapanmaz. Dosyalar el sıkışma başına
diskten okunmaz. Ayrıntılar bölüm tablolarındaki Hot-reload
sütununda ve [`transfer`](#transfer) bölümünde.

## `server`

DNS dinleyicileri ve yönetim arayüzleri.

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `bind` | `[]string` | `["0.0.0.0", "::"]` | hayır | Dinleme adresleri (IPv4 + IPv6) |
| `port` | int | `53` | hayır | UDP/TCP DNS portu |
| `udp_workers` | int | `0` (auto: NumCPU\*4) | hayır | UDP worker sayısı |
| `tcp_workers` | int | `0` (auto: NumCPU\*2) | hayır | TCP worker sayısı |
| `tls.enabled` | bool | `false` | hayır (DoT dinleyicisi yalnızca başlangıçta açılır/kapatılır) | DoT (DNS over TLS) etkinleştir |
| `tls.cert_file` | string | — | içerik evet (SIGHUP / `POST /api/v1/config/reload` dosyayı yeniden okur; SNI'lı ve SNI'sız yeni el sıkışmalar yeni sertifikayı alır, açık bağlantılar eskisini korur; yüklenemezse eski sertifika kalır ve hata loglanır); yol değişikliği yeniden başlatma gerektirir | TLS sertifika yolu (`quic.*`/`xot.*` boşsa DoQ ve XoT de bunu kullanır) |
| `tls.key_file` | string | — | `tls.cert_file` ile aynı | TLS özel anahtar yolu |
| `quic.cert_file` | string | `tls.cert_file` | `tls.cert_file` ile aynı (DoQ) | DoQ (RFC 9250) TLS sertifikası |
| `quic.key_file` | string | `tls.key_file` | `tls.cert_file` ile aynı (DoQ) | DoQ TLS özel anahtarı |
| `tls.bind` | string | `:853` | hayır | DoT dinleme adresi |
| `xot.enabled` | bool | `false` | hayır | XoT (Zone Transfer over TLS, RFC 9103). Deny-by-default: `ca_file` (mTLS) veya `allowed_networks` olmadan sunucu başlamaz |
| `xot.cert_file` | string | — | `tls.cert_file` ile aynı (XoT) | XoT TLS sertifikası (TLS sertifikası yeniden kullanılabilir) |
| `xot.key_file` | string | — | `tls.cert_file` ile aynı (XoT) | XoT TLS özel anahtarı |
| `xot.ca_file` | string | "" | içerik evet: SIGHUP CA paketini yeniden okur; yeni el sıkışmalar (oturum devamı/resumption dahil) yeni havuza göre doğrulanır, çıkarılan CA'nın istemcileri reddedilir; okunamaz/geçersizse eski havuz kalır. mTLS'i sonradan açmak (boş → dolu) veya yol değişikliği yeniden başlatma gerektirir | İstemci sertifikası gerekli kılmak için CA dosyası |
| `xot.allowed_networks` | `[]string` | `[]` | hayır | XoT isteyebilecek istemci CIDR'ları. `ca_file` yoksa en az bir giriş zorunludur |
| `xot.bind` | string | `:853` | hayır | XoT dinleme adresi. `tls.enabled` ile birlikte kullanılıyorsa `tls.bind`'den farklı olmalıdır (ikisinin varsayılanı da `:853`; aynı adres doğrulama hatasıdır) |
| `xot.min_tls_version` | int | `12` | — | **Etkisiz (uyumluluk için):** XoT her zaman yalnızca TLS 1.3 kullanır (RFC 9103) ve ALPN `dot` sunar; `12` yazılsa da TLS 1.2 kabul edilmez. Yalnızca `12` veya `13` değerleri doğrulamadan geçer |
| `http.enabled` | bool | `false` | hayır | HTTP API ve dashboard (yazılmazsa kapalı) |
| `http.bind` | string | `:8080` | hayır | HTTP dinleme adresi. **⚠️ GÜVENLİK RİSKİ:** `0.0.0.0:8080` tüm ağ arayüzlerini dinler — aynı ağdaki herhangi bir saldırgan API'ye ve dashboard'a erişebilir. Production'da: (1) reverse proxy arkasında `127.0.0.1:8080` kullanın, (2) TLS etkinleştirin, veya (3) firewall ile kısıtlayın. Ayrıntılar: `docs/SECURITY.md#api-security` |
| `http.tls_cert_file` | string | "" | `tls.cert_file` ile aynı (HTTPS API/DoH) | HTTP API'yi HTTPS ile sunmak için sertifika (`tls_key_file` ile birlikte) |
| `http.tls_key_file` | string | "" | `tls.cert_file` ile aynı (HTTPS API/DoH) | HTTPS özel anahtarı |
| `http.allowed_origins` | `[]string` | — | hayır (API sunucusu ve dashboard değeri başlangıçta kopyalar) | CORS izin verilen originler. **⚠️ GÜVENLİK:** Public bind'da wildcard (`["*"]`) production validator tarafından **reddedilir**. Production'da açık liste kullanın: `["https://dns.example.com"]` |
| `http.auth_token` | string | "" | hayır | API bearer token (boş = auth yok) |
| `http.users` | []object | — | hayır (kullanıcı deposu başlangıçta kurulur; çalışma anında kullanıcılar API/dashboard ile yönetilir) | Çoklu kullanıcı: `username`, `password`, `role` (admin/operator/viewer). Bu kullanıcılar API/dashboard üzerinden **silinemez, parolası veya rolü değiştirilemez** (`409 user is defined in the config file; change it there`); değişiklik config dosyasında yapılır. `GET /api/v1/auth/users` bunları `config_defined: true` ile işaretler |
| `http.auth_secret` | string | otomatik | hayır | Token imzalama anahtarı (boşsa her açılışta rastgele üretilir; restart'ta tüm oturumlar kapanır) |
| `http.users_file` | string | `<storage.data_dir>/users.json` | hayır | Bootstrap, dashboard veya API ile oluşturulan kullanıcıların saklandığı dosya (0600). `storage.data_dir` de boşsa bu kullanıcılar yalnızca bellekte tutulur ve restart'ta kaybolur. Config'teki `http.users` her zaman önceliklidir ve dosyaya yazılmaz |
| `http.doh_enabled` | bool | `false` | hayır (HTTP uç noktaları başlangıçta kaydedilir) | DNS over HTTPS (RFC 8484) |
| `http.doh_path` | string | `/dns-query` | hayır | DoH yolu |
| `http.dows_enabled` | bool | `false` | hayır | DNS over WebSocket |
| `http.dows_path` | string | `/dns-ws` | hayır | DoWS yolu |
| `http.odoh_enabled` | bool | `false` | hayır | Oblivious DoH (RFC 9230) |
| `http.odoh_path` | string | `/odoh` | hayır | ODoH yolu |

## `resolution`

Recursive resolver davranışı.

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `recursive` | bool | `false` | evet: reload iteratif resolver'ı yeniden kurar; `false` iteratif çözümlemeyi hemen durdurur (sorgular upstream'e gider), `true` başlatır. `PUT /api/v1/config/resolution` değeri kaydeder, sonraki reload/başlangıçta uygulanır | Recursive çözümlemeyi etkinleştir |
| `root_hints` | string | "" | evet (dosya reload'da yeniden okunur; okunamazsa reload iptal edilir) | Root hints dosya yolu (boş = built-in) |
| `max_depth` | int | `10` | evet (resolver yeniden kurulur; API değeri kaydeder, sonraki reload'da uygulanır) | Maksimum delegation takibi derinliği |
| `timeout` | duration | `5s` | evet (upstream istemcisi/load balancer ve iteratif resolver yeni değerle kurulur) | Upstream/iterative sorgu timeout'u; iteratif çözümlemede ayrıca tek bir çözümlemenin toplam süre sınırıdır (en fazla `30s`) |
| `edns0_buffer_size` | int | `4096` | evet (resolver yeniden kurulur) | Reklam edilen EDNS(0) UDP buffer |
| `qname_minimization` | bool | `true` | evet (resolver yeniden kurulur) | QNAME minimization (RFC 7816) |
| `use_0x20` | bool | `false` | evet (resolver yeniden kurulur) | 0x20 harf kipi karıştırma |

## `upstream`

Upstream DNS sunucu havuzu (recursive değilken kullanılır).

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `servers` | []string | `[8.8.8.8:53, 8.8.4.4:53]` | evet (API ile ekleme/çıkarma da canlıdır ve `runtime_overrides.json`'a yazılır) | Upstream listesi (port dahil) |
| `strategy` | string | `random` | evet | `random`, `round_robin`, `fastest` |
| `health_check` | duration | `30s` | evet | Sağlık kontrolü periyodu |
| `failover_timeout` | duration | `5s` | evet (yalnızca `anycast_groups` ile kullanılır) | Failover'a kadar bekleme |
| `topology.region` | string | "" | evet (yalnızca `anycast_groups` ile kullanılır) | Coğrafi etiket |
| `topology.zone` | string | "" | evet (yalnızca `anycast_groups` ile kullanılır) | AZ etiketi |
| `topology.weight` | int | `100` | evet (yalnızca `anycast_groups` ile kullanılır) | Yük dağıtım ağırlığı |

## `cache`

LRU cache ayarları.

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `true` | hayır | Cache'i etkinleştir |
| `size` | int | `10000` | evet (çalışan cache'e uygulanır; `PUT /api/v1/config/cache` ile de canlı) | Maksimum giriş sayısı |
| `default_ttl` | int (s) | `300` | evet (çalışan cache'e uygulanır; `PUT /api/v1/config/cache` ile de canlı) | Varsayılan TTL |
| `max_ttl` | int (s) | `86400` | evet (çalışan cache'e uygulanır; `PUT /api/v1/config/cache` ile de canlı) | TTL üst sınır |
| `min_ttl` | int (s) | `5` | evet (çalışan cache'e uygulanır; `PUT /api/v1/config/cache` ile de canlı) | TTL alt sınır |
| `negative_ttl` | int (s) | `60` | evet (çalışan cache'e uygulanır; `PUT /api/v1/config/cache` ile de canlı) | Negative cache TTL'i (RFC 2308) |
| `prefetch` | bool | `false` | evet (çalışan cache'e uygulanır; `PUT /api/v1/config/cache` ile de canlı) | Yakında dolacak girişleri prefetch et |
| `prefetch_threshold` | int (s) | `60` | evet (çalışan cache'e uygulanır; `PUT /api/v1/config/cache` ile de canlı) | Prefetch tetik eşiği |
| `serve_stale` | bool | `false` | evet | Upstream başarısızken süresi dolmuş girişi sun (RFC 8767) |
| `stale_grace_secs` | int (s) | `86400` | evet | Süresi dolmuş girişin sunulabileceği süre |

`size` küçültülürse fazla girişler yeni girişler eklendikçe çıkarılır.

## `logging`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `level` | string | `info` | evet (`PUT /api/v1/config/logging` ile de canlı; kaydedilen değer YAML'ı ezer) | `debug`, `info`, `warn`, `error`, `fatal` |
| `format` | string | `text` | evet | `text` veya `json` |
| `output` | string | `stdout` | hayır | `stdout`, `stderr` veya mutlak dosya yolu (ekleme kipinde açılır; logrotate ile `copytruncate` kullanın) |
| `query_log` | bool | `false` | hayır (audit logger başlangıçta açılır) | Sorgu audit log'unu etkinleştir |
| `query_log_file` | string | "" | hayır | Sorgu log dosyası, mutlak yol (boş = stdout) |

## `metrics`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `false` | hayır | Prometheus exporter |
| `bind` | string | `:9153` | hayır | Metrik dinleme adresi. `auth_token` yoksa yalnızca loopback (`127.0.0.1:9153`) kabul edilir; aksi halde sunucu başlamaz ve `-validate-config` hata verir |
| `path` | string | `/metrics` | hayır | Metrik HTTP yolu |
| `auth_token` | string | "" | hayır | `Authorization: Bearer` token'ı. Loopback dışı bir `bind` için zorunlu |

## `tracing`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `false` | hayır | OpenTelemetry tracing'i etkinleştir |
| `level` | string | `basic` | hayır | `none`, `basic`, `detailed`, `verbose` |
| `sample_rate` | float | `1.0` | hayır | Tutulan trace oranı (0.0–1.0; SDK `ParentBased(TraceIDRatioBased)` sampler) |
| `endpoint` | string | "" | hayır | OTLP collector endpoint'i (ör. `http://localhost:4318`); yol içermeyen URL'lere otomatik `/v1/traces` eklenir, boşsa `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` / `OTEL_EXPORTER_OTLP_ENDPOINT` env değişkenlerine düşer |

Span'ler `BatchSpanProcessor` ile **OTLP/HTTP+protobuf** üzerinden collector'a
gönderilir; graceful shutdown'da flush edilir. HTTP API middleware'i **W3C Trace
Context** (`traceparent`/`tracestate`) extract/inject yapar — gelen istekler
upstream trace'ine katılır, downstream çağrılar trace'i devam ettirir. Endpoint
yoksa ve env değişkenleri de boşsa span'ler dışa aktarılmaz (yalnızca sınırlı
in-memory kayıt). Tracer yalnızca başlangıçta oluşturulur — değişiklik için
yeniden başlatma gerekir.

## `dnssec`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `true` | evet: validator reload'da kurulur/kaldırılır ve iteratif resolver giden sorgularda DO bitiyle yeniden kurulur | Validation'ı etkinleştir (yerleşik IANA root anchor'ları ile varsayılan olarak açık; kapatmak için açıkça `false` yazın) |
| `trust_anchor` | string | "" | evet | Trust anchor dosyası (boş = built-in) |
| `ignore_time` | bool | `false` | evet | İmza geçerlilik zamanını ignore et (test için) |
| `require_dnssec` | bool | `false` | evet | DNSSEC zorunlu — imzasız cevaplar SERVFAIL |
| `signing.enabled` | bool | `false` | hayır (zone imzalayıcıları başlangıçta kurulur; SIGHUP ile eklenen yeni bir zone yeniden başlatmaya kadar imzasız sunulur) | Yetkili zone'ları imzala |
| `signing.signature_validity` | duration | `720h` | hayır | İmza geçerlilik süresi |
| `signing.keys` | []object | — | hayır | KSK/ZSK key tanımları (`private_key`, `type`, `algorithm`) |
| `signing.nsec3.iterations` | int | `0` | evet | NSEC3 iteration sayısı; en fazla 150 (daha büyük değerler doğrulamada reddedilir, RFC 9276), önerilen 0 |
| `signing.nsec3.salt` | string | "" | evet | NSEC3 salt (hex) |
| `signing.nsec3.opt_out` | bool | `false` | evet | NSEC3 opt-out: imzasız (DS'siz) delegasyonlar zincirden çıkarılır |

`signing.nsec3` bloğu yazıldığında sunucunun **çevrim içi** (sorgu anında)
imzalanan negatif yanıtları NSEC yerine NSEC3 (RFC 5155) taşır ve apex'te
NSEC3PARAM yanıtlanır; ayar her sorguda okunduğu için SIGHUP ile mod hemen
değişir. Blok yoksa NSEC kullanılır. `signature_validity` ve `nsec3`
denetimleri yalnızca `dnssec.enabled` ve `signing.enabled` birlikte açıkken
yapılır.

**Doğrulama iş sınırları (yapılandırılamaz, tasarım gereği):** KeyTrap
(CVE-2023-50387) ve NSEC3 hash taşması (CVE-2023-50868) saldırılarına karşı
validator, BIND/Unbound gibi sabit sınırlar uygular
(`internal/dnssec/validator.go`, `crypto.go`): RRset başına 8 imza
doğrulaması; yanıt başına 128 imza doğrulaması, 512 NSEC3 hash'i ve 64
zone-cut (DS) sorgusu; yanıt başına en fazla 32 Answer RRset'i; bir
inkârda (Authority) en fazla 16 NSEC/NSEC3 RRset'i; delegasyon başına 32
DS × DNSKEY karşılaştırması; zincir derinliği 20. Herhangi bir sınır aşılırsa
yanıt **Bogus** sayılır ve `dnssec.enabled: true` iken SERVFAIL (EDE 6)
döner. 150'den fazla iterasyonlu NSEC3 kayıtları hiç hash'lenmez; onlara
dayanan inkâr kanıtlanamaz ve Bogus olur (RFC 9276 §3.2 insecure veya
SERVFAIL'e izin verir; NothingDNS kapalı başarısız olur). Gerekçe ve tablo:
[SPECIFICATION §6.2.1](SPECIFICATION.md#621-validation-work-limits-fixed-by-design).

**Zone-cut güven modeli:** Bir RRset yalnızca onu içeren zone tarafından
doğrulanabilir (RFC 4035 §5.3.1). İmzalayan zone'un bir etiketten daha
altındaki adlar için aradaki her adın zone cut olmadığı DS sorgusuyla
kanıtlanır (kanıt yoksa veya cut varsa Bogus; negatif yanıtlar da aynı
denetimden geçer). Bilinçli olarak kabul edilen tek durum: sahibi bir alt
zone'un apex'i olan, üst zone tarafından imzalanmış apex dışı tipte veri
(A/AAAA/MX/TXT…). Bunu kapatmak neredeyse her yanıt sahibi için bir DS
sorgusu gerektirir ve 715f339 commit'ini geri alır; istismarı için eski
(delegasyon öncesi, hâlâ geçerli) bir üst zone imzası veya kötü niyetli
bir üst zone gerekir (bkz. SPECIFICATION §6.2.2).

## `cluster`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `false` | hayır | Cluster modu |
| `node_id` | string | "" | hayır | Bu node'un benzersiz kimliği |
| `bind_addr` | string | "" | hayır | Gossip bind adresi |
| `gossip_port` | int | `7946` | hayır | Gossip port |
| `region` | string | "" | hayır | Bölge etiketi |
| `zone` | string | "" | hayır | AZ etiketi |
| `weight` | int | `100` | hayır | Cluster yük ağırlığı |
| `seed_nodes` | []string | `[]` | hayır | Bootstrap için seed listesi (`addr:port`) |
| `cache_sync` | bool | `true` | hayır | Cache invalidation'ı node'lar arası yay |
| `dns_advertise_addr` | string | "" | hayır (yeniden başlatma gerekir: node kimliğinin parçasıdır, cluster başlarken Raft katmanına verilir ve leader tarafından Raft mesajlarıyla duyurulur; türetildiği `tcp_bind`/`bind` dinleyicileri de reload'da değişmez) | Bu node'un cluster'a duyurduğu DNS TCP adresi (`host:port`, joker olmayan host, port 1-65535). Boşsa ilk somut `server.tcp_bind`/`bind` adresi kullanılır; yalnızca joker bind (`0.0.0.0`/`::`) varsa hiçbir adres duyurulmaz. Raft modunda `forward_updates` açık follower'lar imzalı UPDATE'leri leader'ın bu adresine yönlendirir |
| `forward_updates` | bool | `false` | evet | Raft modunda follower'ın, sunduğu bir zone için aldığı TSIG imzalı RFC 2136 UPDATE'i leader'a yönlendirmesi (RFC 2136 §6). `false` (varsayılan, BIND gibi): follower `REFUSED` döner; istemci UPDATE'i leader'a göndermelidir. **Uyarı:** leader yönlendirilen UPDATE'i follower'ın adresinden görür; leader'daki `transfer.tsig_keys[].allowed_cidrs` ve ACL denetimleri istemcinin değil follower'ın adresine uygulanır — CIDR kısıtlı anahtarlar follower adreslerini de içermelidir. Raft modunda `true` iken node bir DNS adresi duyurabilmelidir (`dns_advertise_addr` veya somut, joker olmayan `server.tcp_bind`/`bind`), aksi halde yapılandırma doğrulama hatasıdır. Tüm node'larda aynı değer önerilir |

**Rolling upgrade (karışık sürümlü cluster):** Aşağıdaki çoğaltılan
biçimler eklemelidir (eski node'un apply döngüsü kilitlenmez), ancak eski
bir node ayrışabilir ve ancak yeni bir snapshot kurduğunda yakınsar. Sağdaki
özelliği kullanmadan önce **tüm** node'ları yükseltin:

- 4 MiB'tan büyük snapshot'lar parçalı (chunked) gönderilir — eski follower
  kuramaz ve geride kalır.
- Tek kayıt silme (`del_record` + RDATA, API) — eski node tüm RRset'i siler.
- Atomik zone batch (Raft modunda Dynamic DNS) — eski node "missing
  nameservers" loglar, hiçbir şey uygulamaz.
- SOA önkoşullu UPDATE'ler (batch payload `v: 2`) — yalnızca v1 bilen node
  deterministik olarak reddeder (hiçbir şey uygulanmaz).
- `forward_updates` — leader DNS adresi AppendEntries'e isteğe bağlı bir ek
  alan olarak eklenir; eski follower yok sayar, eski leader göndermez
  (yönlendiren follower `SERVFAIL` döner).
- TSIG'li çok mesajlı AXFR/IXFR artık RFC 8945 zincirini kullanır; eski
  sürümün bağlanmamış zinciri yeni istemcilerce reddedilir (eski sürümde de
  NothingDNS'ler arası anahtarlı AXFR çalışmıyordu). Primary ve
  secondary'leri birlikte yükseltin; tek mesajlı TSIG değişmedi; üçüncü
  taraf sunucularla çok mesajlı zincir uyumu henüz kanıtlanmadı.

Ayrıntı: [SPECIFICATION §10.4](SPECIFICATION.md#104-rolling-upgrades-mixed-version-clusters).

## `blocklist`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `false` | evet | Domain bloklamayı etkinleştir |
| `files` | []string | `[]` | evet | Yerel hosts-format blocklist dosyaları |
| `urls` | []string | `[]` | evet | Otomatik indirilen blocklist URL'leri |
| `base_dir` | string | `""` | evet | Dosya kaynaklarını bu dizinle sınırlar (symlink'ler çözülerek). API üzerinden çalışma anında dosya eklemek için zorunludur |

## `zones`

```yaml
zones:
  - /etc/nothingdns/zones/example.com.zone
```

BIND format yetkili zone dosyalarının liste — hot-reload destekler.

## `acl`

Tüm sorgulara uygulanan genel erişim kontrolü (sunucunun kendi zone'ları dahil).

```yaml
acl:
  - name: "block-abuser"
    action: deny       # allow | deny | redirect
    networks:
      - 198.51.100.0/24
      - "2001:db8:bad::/48"   # IPv6 tırnaksız da okunur; tırnak önerilir
    # types:           # ⚠️ Kuralı belirli QTYPE'lara daraltır.
    #   - MX           #    HER tip için eşleşsin istiyorsanız BU ALANI YAZMAYIN.
    #                  #    "ANY" tüm tipler demek DEĞİLDİR — QTYPE 255'tir; öyle
    #                  #    bir kural yalnızca literal ANY sorgularıyla eşleşir.
```

- `action` küçük harfle yazılmalıdır: `allow`, `deny` veya `redirect` (`Deny` hata verir). `redirect` için `redirect:` alanında bir alan adı zorunludur (yanıt bu ada CNAME'dir).
- `networks`: CIDR veya tek IP.
- `types` (büyük/küçük harf duyarsız) yalnızca şu adları kabul eder; diğerleri (`TYPE123` gibi sayısal biçim, `DLV`, `TKEY` …) yüklemeyi başarısız kılar:

  | Grup | Tipler |
  |---|---|
  | Temel | `A` `AAAA` `NS` `CNAME` `DNAME` `SOA` `PTR` `MX` `TXT` `SRV` `NAPTR` `CAA` `SPF` `HINFO` `RP` `AFSDB` `LOC` `KX` `CERT` `APL` `URI` |
  | DNSSEC | `DS` `DNSKEY` `RRSIG` `NSEC` `NSEC3` `NSEC3PARAM` `CDS` `CDNSKEY` `SIG` `KEY` `TA` |
  | Güvenlik/servis | `TLSA` `SSHFP` `OPENPGPKEY` `IPSECKEY` `HIP` `DHCID` `SVCB` `HTTPS` `ZONEMD` |
  | Meta/sorgu | `AXFR` `IXFR` `ANY` `OPT` `TSIG` |

- ACL, istemci adresi bilinmeyen isteklerde de değerlendirilir: adres hiçbir kurala uymaz, yani kural varsa REFUSED alır. ODoH'ta istemci adresi target'a HTTP ile bağlanan eştir (normalde oblivious proxy) — bkz. [`odoh`](#odoh).
- Kural yoksa (`acl: []` ya da hiç yazılmamışsa) **her istemci** sunucunun kendi kayıtlarını sorgulayabilir.
- Kural varsa sırayla değerlendirilir, ilk eşleşen kazanır; **hiçbir kurala uymayan istemci REFUSED** alır.
- Hot-reload destekler; `<storage.data_dir>/access_policy.json` varsa (dashboard/API değişiklikleri) reload'da da config dosyasındaki `acl` yerine o kullanılır (bkz. aşağı).

## `allow_recursion`

Recursion kullanabilecek istemciler: upstream'e yönlendirme, iterative çözümleme ve önbellekten yanıt. Listede olmayan (ama genel ACL'i geçen) istemciler sunucunun **kendi zone'larından** yanıt almaya devam eder; bunun dışındaki adlar için `REFUSED` (EDE 18 "Prohibited") döner ve yanıtlarda `RA` biti 0 olur. Önbellek bu istemcilere sunulmaz (cache snooping önlemi).

```yaml
allow_recursion:
  - 127.0.0.0/8
  - "::1/128"
  - 192.168.1.0/24
  - 203.0.113.10        # tek IP de yazılabilir (/32 veya /128 olarak saklanır)
```

| Durum | Recursion kimlere açık |
|---|---|
| `allow_recursion` yazılmış | Yalnızca listedeki ağlar (`[]` = kimse) |
| `allow_recursion` yok, `server.acl_allow_unrestricted_recursion: true` | ACL'i geçen herkes (açık resolver — önerilmez) |
| `allow_recursion` yok, `acl` kuralları var | ACL'i geçen herkes (eski davranış) |
| İkisi de yok | Loopback ve özel ağlar: `127.0.0.0/8`, `::1/128`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `fe80::/10` |

**Dashboard / API ile yönetim:** ACL sayfasındaki "Allow Recursion" bölümünden (veya `PUT /api/v1/acl/recursion`) ağ eklenip çıkarılabilir; yalnızca admin rolü değiştirebilir. Değişiklikler `<storage.data_dir>/access_policy.json` dosyasına (0600) yazılır ve bu dosya varsa başlangıçta ve reload'da config dosyasındaki `acl` ile `allow_recursion` değerlerinin **yerine geçer**. `storage.data_dir` tanımlı değilse değişiklikler yalnızca bellekte kalır. Config dosyasına geri dönmek için servisi durdurup `access_policy.json` dosyasını silin.

## `slave_zones`

```yaml
slave_zones:
  - zone_name: "slave.example.com."
    masters:
      - 192.168.1.1:53
    transfer_type: ixfr   # ixfr veya axfr
    tsig_key_name: ""
    tsig_secret: ""
    timeout: 30s
    retry_interval: 5m
    max_retries: 3
```

AXFR/IXFR ile master'dan zone alıp barındırma (secondary). `masters` sırayla
denenir; ilk başarılı olan kullanılır. `tsig_key_name` + `tsig_secret` birlikte
verilirse transfer istekleri TSIG ile imzalanır (anahtar adı büyük/küçük harf
duyarsız, sondaki nokta isteğe bağlı; aynı adın farklı slave zone'larda farklı
secret ile kullanılması doğrulama hatasıdır).

| Alan | Tip | Varsayılan | Açıklama |
|---|---|---|---|
| `zone_name` | string | — (zorunlu) | Zone adı |
| `masters` | `[]string` | — (zorunlu) | Master adresleri (`IP:port` veya host adı) |
| `transfer_type` | string | `ixfr` | `ixfr` (AXFR'a geri düşer) veya `axfr` |
| `timeout` | duration | `30s` | Tek transfer denemesinin süre sınırı |
| `retry_interval` | duration | `5m` | Başarısız transferden sonra bekleme — **yalnızca zone ilk kez yüklenene kadar**; sonrasında SOA RETRY geçerlidir |
| `max_retries` | int | `0` (sınırsız) | Ardışık başarısız deneme sınırı. Hiç yüklenmemiş zone: sınıra ulaşınca denemeler durur. Yüklenmiş zone: sayaç sıfırlanır ve sonraki deneme SOA REFRESH süresine ertelenir (yenileme hiç durmaz) |

**Zamanlayıcılar (RFC 1035 §4.3.5):** İlk başarılı transferden sonra zone'un
SOA alanları zamanlamayı belirler: başarıdan REFRESH sonra yeniden kontrol
(IXFR, güncelse tek SOA), başarısızlıktan RETRY sonra yeniden deneme. Değerler
sınırlanır: REFRESH 30 sn–28 gün, RETRY 30 sn–14 gün, EXPIRE en az
REFRESH+RETRY. Son başarılı yenilemeden bu yana EXPIRE dolarsa zone **artık
sunulmaz** (sorgular yerel zone gibi yanıtlanmaz) ve sonraki başarılı
yenilemede yeniden sunulur. Henüz hiç transfer edilmemiş (SOA'sız) bir slave
zone da sunulmaz.

**Gelen NOTIFY:** Bir slave zone için NOTIFY yalnızca o zone'un `masters`
listesindeki bir adresten (host adları çözülerek) kabul edilir ve hemen bir
yenileme tetikler; diğer kaynaklar `REFUSED` alır. `transfer.allow_list` slave
zone NOTIFY'larını yetkilendirmez.

## `transfer`

```yaml
transfer:
  allow_list:
    - 192.0.2.0/24
    - 2001:db8::/32
  require_tsig: false
  tsig_keys:
    - name: xfr-key.example.
      algorithm: hmac-sha256
      secret: "<base64>"
      allowed_cidrs: [192.0.2.0/24]
    - name: ddns-key.example.
      secret: "<base64>"
      allow_update:
        - example.com.
  also_notify:
    - 192.0.2.2:53
  notify_key: xfr-key.example.
```

Yerel authoritative zone'ları AXFR/IXFR ile secondary sunuculara servis eder.
`allow_list` boşsa transfer istekleri deny-by-default reddedilir.
Gelen NOTIFY: `slave_zones` içindeki bir zone için NOTIFY'ı o zone'un
`masters` listesi yetkilendirir (bkz. [`slave_zones`](#slave_zones));
`allow_list` yalnızca diğer zone'lar için gelen NOTIFY'ları kapsar.
`require_tsig: true`, IP allow-list eşleşse bile TSIG doğrulamasını zorunlu kılar.

| Alan | Tip | Varsayılan | Açıklama |
|---|---|---|---|
| `allow_list` | `[]string` | `[]` | AXFR/IXFR isteyebilecek IP/CIDR listesi (boş = tüm transferler reddedilir). Slave zone'lar dışındaki zone'lar için gelen NOTIFY'ları da yetkilendirir |
| `require_tsig` | bool | `false` | TSIG doğrulamasını zorunlu kıl |
| `journal_dir` | string | `storage.data_dir/ixfr-journals` | IXFR journal dizini. Storage'dan bağımsız bir volume'a taşımak için override edin |
| `tsig_keys` | `[]object` | `[]` | TSIG anahtarları (RFC 8945). En az bir anahtar tanımlıysa her AXFR/IXFR bunlardan biriyle imzalanmalıdır (`allow_list` eşleşmesine ek olarak) |
| `tsig_keys[].name` | string | — (zorunlu) | Anahtar adı (ör. `xfr-key.example.`). Alan adı olarak karşılaştırılır: büyük/küçük harf duyarsız, sondaki nokta isteğe bağlı (`XFR-Key` = `xfr-key.`; ikisini birden yazmak "duplicate key name" hatasıdır). Yanıtlar kanonik adla (küçük harf, sonda nokta) imzalanır |
| `tsig_keys[].algorithm` | string | `hmac-sha256` | `hmac-sha1`, `hmac-sha224`, `hmac-sha256`, `hmac-sha384`, `hmac-sha512` (HMAC-MD5 desteklenmez) |
| `tsig_keys[].secret` | string | — (zorunlu) | Base64 paylaşılan sır (tsig-keygen formatı, en az 16 bayt) |
| `tsig_keys[].allowed_cidrs` | `[]string` | `[]` | Anahtarı kullanabilecek istemci CIDR'ları (boş = kısıtlama yok); transfer ve UPDATE için geçerli |
| `tsig_keys[].allow_update` | `[]string` | `[]` | Bu anahtarın RFC 2136 Dynamic DNS UPDATE ile değiştirebileceği zone'lar (tam zone adı; wildcard, boş veya tekrarlanan ad doğrulama hatasıdır). Boş = güncelleme yetkisi yok |
| `also_notify` | `[]string` | `[]` | Transfer için servis edilen bir zone'un SOA serial'ı değiştiğinde (API/Raft düzenlemesi, Dynamic DNS, SIGHUP reload) RFC 1996 NOTIFY gönderilecek secondary'ler; yalnızca literal `IP:port` (ör. `192.0.2.2:53`, `[2001:db8::2]:53`). Boş = hiç NOTIFY gönderilmez. SIGHUP ile yeniden okunur: eklenen hedefler bir sonraki serial değişikliğinden itibaren NOTIFY alır; çıkarılan hedeflere giden uçuştaki NOTIFY iptal edilir ve yenisi gönderilmez |
| `notify_key` | string | `""` | Giden NOTIFY'ları TSIG ile imzalamak için bir `tsig_keys` girdisinin adı. Boş = imzasız. Var olmayan bir anahtar adı doğrulama hatasıdır. SIGHUP ile yeniden okunur (sonraki gönderimler yeni anahtarla imzalanır) |

**Giden NOTIFY (RFC 1996):** `also_notify` doluysa sunucu, transfer edilebilir
(AXFR/IXFR ile servis edilen) her zone'un serial değişikliğinde her hedefe
asenkron olarak SOA ipuçlu bir NOTIFY gönderir. İstek yolu hiçbir zaman
beklemez; yanıtsız NOTIFY RFC 1996 §3.6'ya göre tekrar gönderilir (5 tekrar,
deneme başına 5 sn). Zone+hedef başına aynı anda tek NOTIFY uçuştadır; bu sırada
gelen değişiklikler birleştirilir: uçuştaki (eskimiş serial'lı) NOTIFY iptal
edilir ve en son serial hemen gönderilir. Başlangıçta, DNS dinleyicileri
açıldıktan sonra her zone için bir kez NOTIFY gönderilir (BIND "notify on
load"; primary kapalıyken yapılan değişiklikleri secondary'lerin almasını
sağlar); başlangıcı geciktirmez. Kapanışta uçuştaki NOTIFY'lar iptal edilir.
`slave_zones` (bu sunucunun secondary olduğu zone'lar) aşağı akışa transfer
edilmediğinden NOTIFY gönderilmez.

**Dynamic DNS (RFC 2136 UPDATE):** Bir UPDATE yalnızca, `allow_update` listesi
hedef zone'u içeren bir `tsig_keys` anahtarıyla TSIG imzalıysa (ve anahtarın
`allowed_cidrs` listesi varsa istemci adresi bu listedeyse) kabul edilir.
İmzasız UPDATE her zaman `REFUSED`; geçerli imzalı ama zone yetkisi olmayan
anahtar `REFUSED`; bilinmeyen anahtar, hatalı MAC veya izin verilmeyen adres
`NOTAUTH` döner. İmzalı isteklere verilen yanıtlar aynı anahtarla TSIG
imzalıdır. `tsig_keys` dışında DDNS için ayrı bir yapılandırma yoktur.

Raft cluster modunda (`cluster.consensus_mode: raft`) kabul edilen bir UPDATE
Raft log'u üzerinden çoğaltılır:

- Bir UPDATE = **tek atomik Raft girdisi** (zone batch): tüm replikalarda ya
  tamamı uygulanır ya hiçbiri; SOA serial bir kez artar.
- Önkoşullar, UPDATE'in dokunduğu adların planlama anındaki durumuna karşı
  denetlenir; arada aynı adlara başka bir yazma gelirse UPDATE yeniden
  planlanır, sürekli çakışırsa `SERVFAIL` (istemci tekrar deneyebilir). SOA
  RRset'ine önkoşul koyan bir UPDATE (ör. serial'e bağlı iyimser kilit) tüm
  zone'a karşı korunur: planlama ile uygulama arasında zone'a herhangi bir
  yazma gelirse yeniden planlanır ve önkoşul yeniden denetlenir (`NXRRSET`).
  Bu koruma zone boyutuyla orantılıdır (~1 µs/kayıt) ve yalnızca SOA
  önkoşullu UPDATE'lerde kullanılır; serial'in kendisi karşılaştırılmaz
  (yalnızca serial'i değiştiren bir yazma çakışma sayılmaz).
- 1024'ten fazla kayıt değişikliği içeren UPDATE `REFUSED`.
- SOA değiştiren UPDATE `REFUSED` (serial'i batch yönetir).
- UPDATE'i yalnızca leader uygular. Varsayılan olarak follower `REFUSED`
  döner. `cluster.forward_updates: true` ise follower, yerelde sunduğu bir zone için
  TSIG imzalı UPDATE'i değiştirmeden leader'ın duyurduğu DNS adresine
  (`cluster.dns_advertise_addr`) TCP ile yönlendirir (RFC 2136 §6) ve
  leader'ın yanıtını aynen (TSIG imzası dahil) istemciye iletir. Follower
  yetkilendirme yapmaz: TSIG ve `allow_update` denetimini leader yapar.
  Leader bilinmiyorsa, leader adres duyurmuyorsa, 5 sn içinde yanıt yoksa
  veya aynı anda 64'ten fazla yönlendirme varsa `SERVFAIL` (tekrar
  denenebilir). İmzasız UPDATE yönlendirilmez (`REFUSED`). Leader, isteği
  follower'ın adresinden görür: `allowed_cidrs` / ACL denetimleri
  yönlendirilen UPDATE'lerde istemcinin değil follower'ın adresine uygulanır.
  Döngü koruması: node yalnızca leader değilken ve yalnızca izlediği güncel
  leader'a (kendi adresi hariç) yönlendirir; liderliğini kaybetmiş bir node
  daha yeni bir term'e geçmiş olduğundan her ek atlama daha yeni bir term'in
  leader'ına gider, döngü oluşamaz.
- **Rolling upgrade:** Raft DDNS'i kullanmadan önce tüm node'lar zone batch
  destekleyen sürümde olmalıdır; eski bir node batch'i atlar ve bir sonraki
  snapshot kurulumuna kadar diğerlerinden ayrışır.
  SOA önkoşullu UPDATE'ler ayrıca yeni bir batch biçimi (payload `v: 2`,
  `"zone": true`) kullanır: yalnızca v1'i bilen bir node bu batch'i
  deterministik olarak reddeder (hiçbir değişiklik uygulanmaz, uyarı loglanır)
  ve bir sonraki snapshot kurulumuna kadar ayrışır. Bu yüzden SOA önkoşullu
  UPDATE göndermeden önce tüm node'lar bu desteği içeren sürüme
  yükseltilmelidir; SOA önkoşulu olmayan UPDATE'ler v1 olarak kalır.

Bir `allow_update` anahtarı aynı zamanda transfer anahtarıdır:
`allow_list` içindeki bir adresten AXFR/IXFR imzalamak için de kullanılabilir.
**SIGHUP ile anahtar değişiklikleri:** `tsig_keys` SIGHUP ile yeniden okunur
ve yeniden başlatma gerektirmez: eklenen anahtarlar, çıkarılan anahtarlar,
değişen `secret` (anahtar rotasyonu), `allowed_cidrs` ve `allow_update`
yetkileri AXFR/IXFR, Dynamic DNS ve `notify_key` ile imzalanan giden NOTIFY
için reload tamamlandığı anda geçerlidir. Değişiklik atomiktir: reload
sırasında doğrulanmakta olan bir AXFR/IXFR/UPDATE eski anahtar kümesiyle
tamamlanır, reload bu isteklerin bitmesini bekler; reload'dan sonra başlayan
her istek yalnızca yeni kümeyi görür — çıkarılan bir anahtar hemen
reddedilir (`NOTAUTH` / transfer `REFUSED`). Raft modunda leader'da zaten
yetkilendirilmiş bir UPDATE'in commit'i reload'ı beklemez. Rotasyonda eski
secret için ek bir geçiş süresi yoktur; secondary'ler ve DDNS istemcileri
yeni secret'a reload ile aynı anda geçirilmelidir (veya geçiş için geçici
olarak farklı adlı ikinci bir anahtar tanımlanmalıdır).
`slave_zones[].tsig_secret` değişiklikleri de SIGHUP ile yüklenir; slave
zone'un bir sonraki transferi yeni secret ile imzalanır. `slave_zones`
listesinin kendisi (zone, `masters`, `tsig_key_name`) ve `allow_list` /
`require_tsig` yeniden başlatma gerektirir; reload'da adı yapılandırmadan
kalkan bir anahtarı kullanan çalışan slave zone uyarı loglar ve yeniden
başlatmaya kadar transfer yapamaz.

## `views` — Split-Horizon DNS

```yaml
views:
  - name: internal
    match_clients: [10.0.0.0/8, 192.168.0.0/16]
    zone_files:
      - /etc/nothingdns/views/internal/example.com.zone

  - name: external
    match_clients: [any]
    zone_files:
      - /etc/nothingdns/views/external/example.com.zone
```

Sırayla değerlendirilir; ilk eşleşen view'ın zone dosyaları sunulur.

## `rpz` — Response Policy Zones

```yaml
rpz:
  enabled: false
  zones:
    - name: "rpz.example.com"
      file: /etc/nothingdns/rpz/blocklist.rpz
      priority: 1
```

Düşük priority önce çalışır. Aksiyonlar: NXDOMAIN, NODATA, redirect, DROP.

## `geodns`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `false` | evet | GeoIP-based yanıt seçimi |
| `mmdb_file` | string | — | evet | MaxMind MMDB dosya yolu |

## `idna`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `false` | evet | Sorgu adlarının IDNA2008 doğrulaması (RFC 5891 §5.4, RFC 5892); geçersiz ad FORMERR (EDE 18) alır. Her U-label (Unicode etiket ya da kodu çözülmüş `xn--` A-label) NFC olmalı, 3–4. konumda `--` ve başta birleştirici işaret içermemeli; her code point RFC 5892 türetilmiş özelliğine göre PVALID olmalı ya da CONTEXTJ/CONTEXTO kuralını (Ek A.1–A.9) sağlamalı — DISALLOWED karakterler (ör. emoji, U+0640 tatweel, büyük harfler, tam genişlikli harfler) reddedilir. Unicode girdi önce küçük harfe çevrilip NFC'ye normalize edilir |
| `use_std3_rules` | bool | `true` | evet | STD3 ASCII kuralları: etiketler yalnızca harf, rakam ve iç tire içerebilir. `false` = her ASCII etiket kabul edilir (ör. `_dmarc`, `_sip._tcp`); uzunluk sınırları yine uygulanır |
| `allow_unassigned` | bool | `false` | evet | `false` = Unicode'da atanmamış (RFC 5892 UNASSIGNED) code point içeren U-label (ya da kodu çözülen `xn--` A-label) reddedilir; `true` = bu code point'ler kabul edilir (diğer IDNA2008 kuralları yine uygulanır) |
| `check_bidi` | bool | `true` | evet | RFC 5893 §2 Bidi kuralı (RTL etiket içeren adların tüm etiketlerine). Bidi_Class, Go standart kütüphanesiyle aynı Unicode sürümünün tam Bidi_Class tablosundan okunur (`internal/idna/tables<sürüm>.go`, Go 1.26: Unicode 15.0.0, Go 1.27+: Unicode 17.0.0); RTL etiket rakamla (EN/AN) bitebilir, ancak aynı etikette EN ve AN birlikte olamaz |
| `check_joiner` | bool | `true` | — (kullanımdan kaldırıldı, etkisiz: RFC 5892 CONTEXTJ kuralları (ZWNJ/ZWJ, Ek A.1/A.2) `idna.enabled` açıkken her zaman uygulanır, RFC 5891 §5.4 bunu arama için zorunlu kılar; `idna.enabled` açıkken başlangıçta ve reload'da uyarı loglanır) | Joiner (ZWJ/ZWNJ) bağlam kuralları |

`idna.enabled` açıkken her `xn--` etiketi geçerli bir A-label olmalıdır
(RFC 5891 §5.4): kodu çözülüp yeniden kodlandığında kendine dönmeyen, ASCII'ye
çözülen ya da kontrol/boşluk/özel kullanım code point'i içeren `xn--` etiketi
FORMERR (EDE 18) alır; geçerli A-label'ların çözülmüş U-label'ına yukarıdaki
IDNA2008 etiket kuralları ve `allow_unassigned`/`check_bidi` uygulanır (ör.
`xn--ls8h` (emoji), `xn--lsa` (başta birleştirici işaret) ve NFC olmayan
`xn--cafe-yvc` reddedilir). IDNA2008 tabloları (türetilmiş özellik,
Bidi_Class, Joining_Type, normalizasyon) `internal/idna/gen_idna_tables.go`
ile toolchain'in Unicode sürümü için üretilir; RFC 5895 genişlik eşlemesi
uygulanmaz.

## `odoh`

Oblivious DNS over HTTPS (RFC 9230), conformant with RFC 9180 HPKE
base mode. The HPKE math is validated byte-for-byte against the
RFC 9180 §A.1 test vectors. KEM/KDF/AEAD selection is currently
fixed by the implementation; only the values below are accepted.

**ACL ve recursion:** ODoH ile gelen sorgularda `acl` ve `allow_recursion`
için kullanılan istemci adresi, target'a HTTP ile bağlanan eştir — normal
dağıtımda oblivious **proxy**'nin adresi, son istemcininki değil (ODoH'un
amacı budur). Proxy adresine göre kural yazın; adresi çözümlenemeyen bir eş
hiçbir kurala uymaz (kural varsa `REFUSED`).

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `false` | hayır | Oblivious DoH proxy/target |
| `bind` | string | `:8080` | hayır | ODoH dinleme adresi |
| `target_url` | string | — | hayır (ODoH proxy/target başlangıçta kurulur) | ODoH target endpoint URL'i |
| `proxy_url` | string | — | hayır | ODoH proxy URL'i |
| `kem` | int | `32` | hayır | HPKE KEM (RFC 9180 kimliği) — yalnızca `32` (0x0020, DHKEM X25519 / HKDF-SHA256) destekleniyor |
| `kdf` | int | `1` | hayır | HPKE KDF — yalnızca `1` (HKDF-SHA256) destekleniyor |
| `aead` | int | `1` | hayır | HPKE AEAD (RFC 9180 kimlikleri) — `1` (AES-128-GCM, varsayılan) veya `2` (AES-256-GCM). `3` (ChaCha20-Poly1305) desteklenmiyor. |

## Üst Seviye Alanlar

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `memory_limit_mb` | int | `0` | hayır | Bellek üst sınırı (0 = sınırsız); aşımda cache eviction |
| `shutdown_timeout` | duration | `30s` | evet (kapanış anında son yüklenen config'ten okunur) | Graceful shutdown'da in-flight sorgu için bekleme süresi |

## Tam Örnek

[config.example.yaml](../config.example.yaml) içinde tüm alanların annotated
örneği bulunur.
