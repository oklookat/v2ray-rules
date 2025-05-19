# v2ray-rules

Useful v2ray rules. The list of rules may be added to as needed. Or it may not.

## how to use

- you need sing-box > 1.11.0
- copy direct link to rule, then add it to you config. Example:

```json
    "rule_set": [
      {
        "tag": "geoip-reflected-networks",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/oklookat/v2ray-rules/raw/refs/heads/main/sing-box/geoip/reflected-networks.srs"
      }
    ]
```

Then you can use this rule. In general, read the documentation for the sing-box.

## geoip

### reflected-networks

PornHub hosts videos, etc, on Reflected Networks. So, if you want proxy PH, you need this.

## datacamp-limited (CDN77)

AdGuard, Twitch, Udemy, and many others uses CDN77.

## digital-ocean

Very many services uses Ditial Ocean. GitLab, Docker, XVideos, for example.

Use carefully. Many IPs.

## scaleway

[Can be blocked](https://ntc.party/t/%D0%B1%D0%BB%D0%BE%D0%BA%D0%B8%D1%80%D0%BE%D0%B2%D0%BA%D0%B0-%D1%87%D0%B0%D1%81%D1%82%D0%B8-ip-%D0%B0%D0%B4%D1%80%D0%B5%D1%81%D0%BE%D0%B2-scaleway).

## akamai

Big CDN, many sites using it. Example: Spotify. Also can be blocked.

## vultr

SSD VPS Servers, Cloud Servers and Cloud Hosting.

## geosite

### xbox-wdl

Xbox services, except games downloading, etc.

### no-russia

Resources, that blocking russian users, etc.
