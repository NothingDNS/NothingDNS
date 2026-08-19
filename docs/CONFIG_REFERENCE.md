# Configuration Reference

NothingDNS, [config.example.yaml](../config.example.yaml) içinde dağıtılan
tek bir YAML dosyası ile yapılandırılır. Bu belge her üst seviye bölümün
alanlarını ve davranışını açıklar.

Notlar:

- Hot-reload sütunu, SIGHUP ile yeniden yüklendiğinde alanın yeniden
  okunup okunmadığını gösterir.
- `0 = auto` notu, sıfır verilirse runtime'ın varsayılanı hesapladığı
  anlamına gelir.
- YAML parser anchor/alias ve multiline string'leri **desteklemez** — düz
  YAML kullanın.
- **IPv6 CIDR'leri tırnak içine alın**: Özel YAML parser'ımız `::`
  karakterini mapping separator olarak yorumlar. Doğru: `"::1/128"`,
  yanlış: `::1/128`. Bu özellikle ACL `networks` listesinde önemlidir.
  IPv4 CIDR'leri (`192.168.0.0/16`) tırnaksız çalışır.

## `server`

DNS dinleyicileri ve yönetim arayüzleri.

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `bind` | `[]string` | `["0.0.0.0", "::"]` | hayır | Dinleme adresleri (IPv4 + IPv6) |
| `port` | int | `53` | hayır | UDP/TCP DNS portu |
| `udp_workers` | int | `0` (auto: NumCPU\*4) | hayır | UDP worker sayısı |
| `tcp_workers` | int | `0` (auto: NumCPU\*2) | hayır | TCP worker sayısı |
| `tls.enabled` | bool | `false` | evet | DoT (DNS over TLS) etkinleştir |
| `tls.cert_file` | string | — | evet | TLS sertifika yolu |
| `tls.key_file` | string | — | evet | TLS özel anahtar yolu |
| `tls.bind` | string | `:853` | hayır | DoT dinleme adresi |
| `xot.enabled` | bool | `false` | hayır | XoT (Zone Transfer over TLS, RFC 9103) |
| `xot.cert_file` | string | — | evet | XoT TLS sertifikası (TLS sertifikası yeniden kullanılabilir) |
| `xot.key_file` | string | — | evet | XoT TLS özel anahtarı |
| `xot.ca_file` | string | "" | evet | İstemci sertifikası gerekli kılmak için CA dosyası |
| `xot.bind` | string | `:853` | hayır | XoT dinleme adresi |
| `xot.min_tls_version` | int | `12` | evet | `12` = TLS 1.2, `13` = TLS 1.3 |
| `http.enabled` | bool | `true` | hayır | HTTP API ve dashboard |
| `http.bind` | string | `:8080` | hayır | HTTP dinleme adresi. **⚠️ GÜVENLİK RİSKİ:** `0.0.0.0:8080` tüm ağ arayüzlerini dinler — aynı ağdaki herhangi bir saldırgan API'ye ve dashboard'a erişebilir. Production'da: (1) reverse proxy arkasında `127.0.0.1:8080` kullanın, (2) TLS etkinleştirin, veya (3) firewall ile kısıtlayın. Ayrıntılar: `docs/SECURITY.md#api-security` |
| `http.allowed_origins` | `[]string` | — | evet | CORS izin verilen originler. **⚠️ GÜVENLİK:** Public bind'da wildcard (`["*"]`) production validator tarafından **reddedilir**. Production'da açık liste kullanın: `["https://dns.example.com"]` |
| `http.auth_token` | string | "" | evet | API bearer token (boş = auth yok) |
| `http.users` | []object | — | evet | Çoklu kullanıcı: `username`, `password`, `role` (admin/operator/viewer) |
| `http.auth_secret` | string | otomatik | hayır | JWT imzalama anahtarı (boşsa otomatik üretilir, restart'ta korunur) |
| `http.doh_enabled` | bool | `false` | evet | DNS over HTTPS (RFC 8484) |
| `http.doh_path` | string | `/dns-query` | evet | DoH yolu |
| `http.dows_enabled` | bool | `false` | evet | DNS over WebSocket |
| `http.dows_path` | string | `/dns-ws` | evet | DoWS yolu |
| `http.odoh_enabled` | bool | `false` | evet | Oblivious DoH (RFC 9230) |
| `http.odoh_path` | string | `/odoh` | evet | ODoH yolu |

## `resolution`

Recursive resolver davranışı.

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `recursive` | bool | `false` | evet | Recursive çözümlemeyi etkinleştir |
| `root_hints` | string | "" | evet | Root hints dosya yolu (boş = built-in) |
| `max_depth` | int | `10` | evet | Maksimum delegation takibi derinliği |
| `timeout` | duration | `5s` | evet | Upstream/iterative sorgu timeout'u |
| `edns0_buffer_size` | int | `4096` | evet | Reklam edilen EDNS(0) UDP buffer |

## `upstream`

Upstream DNS sunucu havuzu (recursive değilken kullanılır).

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `servers` | []string | `[8.8.8.8:53, 8.8.4.4:53, 1.1.1.1:53]` | evet | Upstream listesi (port dahil) |
| `strategy` | string | `random` | evet | `random`, `round_robin`, `fastest` |
| `health_check` | duration | `30s` | evet | Sağlık kontrolü periyodu |
| `failover_timeout` | duration | `5s` | evet | Failover'a kadar bekleme |
| `topology.region` | string | "" | hayır | Coğrafi etiket |
| `topology.zone` | string | "" | hayır | AZ etiketi |
| `topology.weight` | int | `100` | evet | Yük dağıtım ağırlığı |

## `cache`

LRU cache ayarları.

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `true` | hayır | Cache'i etkinleştir |
| `size` | int | `10000` | evet | Maksimum giriş sayısı |
| `default_ttl` | int (s) | `300` | evet | Varsayılan TTL |
| `max_ttl` | int (s) | `86400` | evet | TTL üst sınır |
| `min_ttl` | int (s) | `5` | evet | TTL alt sınır |
| `negative_ttl` | int (s) | `60` | evet | Negative cache TTL'i (RFC 2308) |
| `prefetch` | bool | `false` | evet | Yakında dolacak girişleri prefetch et |
| `prefetch_threshold` | int (s) | `60` | evet | Prefetch tetik eşiği |

## `logging`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `level` | string | `info` | evet | `debug`, `info`, `warn`, `error`, `fatal` |
| `format` | string | `text` | evet | `text` veya `json` |
| `output` | string | `stdout` | hayır | `stdout` veya `stderr` |
| `query_log` | bool | `false` | evet | Sorgu audit log'unu etkinleştir |
| `query_log_file` | string | "" | evet | Audit log dosyası (boş = output ile aynı) |

## `metrics`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `false` | hayır | Prometheus exporter |
| `bind` | string | `:9153` | hayır | Metrik dinleme adresi |
| `path` | string | `/metrics` | hayır | Metrik HTTP yolu |

## `tracing`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `false` | hayır | OpenTelemetry tracing'i etkinleştir |
| `level` | string | `basic` | hayır | `none`, `basic`, `detailed`, `verbose` |
| `sample_rate` | float | `1.0` | hayır | Tutulan trace oranı (0.0–1.0; SDK `ParentBased(TraceIDRatioBased)` sampler) |
| `endpoint` | string | "" | hayır | OTLP collector endpoint'i (ör. `http://localhost:4318`); boşsa `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` / `OTEL_EXPORTER_OTLP_ENDPOINT` env değişkenlerine düşer |

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
| `enabled` | bool | `false` | evet | Validation'ı etkinleştir |
| `trust_anchor` | string | "" | evet | Trust anchor dosyası (boş = built-in) |
| `ignore_time` | bool | `false` | evet | İmza geçerlilik zamanını ignore et (test için) |
| `require_dnssec` | bool | `false` | evet | DNSSEC zorunlu — imzasız cevaplar SERVFAIL |
| `signing.enabled` | bool | `false` | evet | Yetkili zone'ları imzala |
| `signing.signature_validity` | duration | `720h` | evet | İmza geçerlilik süresi |
| `signing.keys` | []object | — | evet | KSK/ZSK key tanımları (`private_key`, `type`, `algorithm`) |
| `signing.nsec3.iterations` | int | `10` | evet | NSEC3 iteration sayısı |
| `signing.nsec3.salt` | string | "" | evet | NSEC3 salt (hex) |
| `signing.nsec3.opt_out` | bool | `false` | evet | NSEC3 opt-out flag |

## `cluster`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `false` | hayır | Cluster modu |
| `node_id` | string | "" | hayır | Bu node'un benzersiz kimliği |
| `bind_addr` | string | "" | hayır | Gossip bind adresi |
| `gossip_port` | int | `7946` | hayır | Gossip port |
| `region` | string | "" | hayır | Bölge etiketi |
| `zone` | string | "" | hayır | AZ etiketi |
| `weight` | int | `100` | evet | Cluster yük ağırlığı |
| `seed_nodes` | []string | `[]` | hayır | Bootstrap için seed listesi (`addr:port`) |
| `cache_sync` | bool | `true` | evet | Cache invalidation'ı node'lar arası yay |

## `blocklist`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `false` | evet | Domain bloklamayı etkinleştir |
| `files` | []string | `[]` | evet | Yerel hosts-format blocklist dosyaları |
| `urls` | []string | `[]` | evet | Otomatik indirilen blocklist URL'leri |

## `zones`

```yaml
zones:
  - /etc/nothingdns/zones/example.com.zone
```

BIND format yetkili zone dosyalarının liste — hot-reload destekler.

## `acl`

```yaml
acl:
  - name: "allow-local"
    action: allow      # allow | deny
    networks:
      - 127.0.0.0/8
      - "::1/128"      # ⚠️ IPv6 CIDR'leri tırnak içine alın!
    types:
      - ANY            # spesifik QTYPE'lar veya ANY
```

Sırayla değerlendirilir; ilk eşleşme kazanır. Hot-reload destekler.

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

AXFR/IXFR ile master'dan zone alıp barındırma. TSIG anahtarları yapılandırıldıysa
imzalama uygulanır; TSIG IP binding güvenlik düzeltmesi yakın zamanda eklendi.

## `transfer`

```yaml
transfer:
  allow_list:
    - 192.0.2.0/24
    - 2001:db8::/32
  require_tsig: false
```

Yerel authoritative zone'ları AXFR/IXFR ile secondary sunuculara servis eder.
`allow_list` boşsa transfer istekleri deny-by-default reddedilir.
`allow_list`, RFC 1996 NOTIFY isteklerini de yetkilendirir: NOTIFY, slave zone
replikasyonunu tetikleyen sinyal olduğundan, AXFR/IXFR için yetkili bir master'ın
NOTIFY göndermesine de izin verilir; listede olmayan kaynaklardan gelen NOTIFY
reddedilir.
`require_tsig: true`, IP allow-list eşleşse bile TSIG doğrulamasını zorunlu kılar.

| Alan | Tip | Varsayılan | Açıklama |
|---|---|---|---|
| `allow_list` | `[]string` | `[]` | İzin verilen IP/CIDR listesi (boş = tüm transferler ve NOTIFY istekleri reddedilir); AXFR/IXFR ve RFC 1996 NOTIFY için ortak yetkilendirme |
| `require_tsig` | bool | `false` | TSIG doğrulamasını zorunlu kıl |
| `journal_dir` | string | `storage.data_dir/ixfr-journals` | IXFR journal dizini. Storage'dan bağımsız bir volume'a taşımak için override edin |

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
| `database` | string | — | evet | MaxMind MMDB dosya yolu |

## `idna`

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `false` | evet | IDNA validation (RFC 5891) |
| `use_std3_rules` | bool | `false` | evet | STD3 ASCII kuralları |
| `allow_unassigned` | bool | `false` | evet | Atanmamış code point'lere izin ver |

## `odoh`

Oblivious DNS over HTTPS (RFC 9230), conformant with RFC 9180 HPKE
base mode. The HPKE math is validated byte-for-byte against the
RFC 9180 §A.1 test vectors. KEM/KDF/AEAD selection is currently
fixed by the implementation; only the values below are accepted.

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `enabled` | bool | `false` | hayır | Oblivious DoH proxy/target |
| `bind` | string | `:8080` | hayır | ODoH dinleme adresi |
| `target_url` | string | — | evet | ODoH target endpoint URL'i |
| `proxy_url` | string | — | evet | ODoH proxy URL'i |
| `kem` | int | `4` | hayır | HPKE KEM — yalnızca `4` (DHKEM X25519, HKDF-SHA256) destekleniyor |
| `kdf` | int | `1` | hayır | HPKE KDF — yalnızca `1` (HKDF-SHA256) destekleniyor |
| `aead` | int | `1` | hayır | HPKE AEAD — `1` (AES-256-GCM, varsayılan) veya `3` (AES-128-GCM). ChaCha20-Poly1305 stdlib dışı olduğu için desteklenmiyor. |

## Üst Seviye Alanlar

| Alan | Tip | Varsayılan | Hot-reload | Açıklama |
|---|---|---|---|---|
| `memory_limit_mb` | int | `0` | hayır | Bellek üst sınırı (0 = sınırsız); aşımda cache eviction |
| `shutdown_timeout` | duration | `30s` | hayır | Graceful shutdown'da in-flight sorgu için bekleme süresi |

## Tam Örnek

[config.example.yaml](../config.example.yaml) içinde tüm alanların annotated
örneği bulunur.
