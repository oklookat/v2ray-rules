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

## geosite

### xbox-wdl

Xbox services, except games downloading, etc.
