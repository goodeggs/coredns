# sign

## Name

*sign* - add DNSSEC records to zone files.

## Description

The *sign* plugin is used to sign (see RFC 6781) zones. In this process DNSSEC resource records
are added. The signatures have a expiration date, so the signing process must be repeated every so
often, otherwise the zone's data will go BAD (RFC 4035, Section 5.5). The *sign* plugin takes care
of this.

Only NSEC is supported, *sign* does not support NSEC3.

*Signs* works in conjunction with the *file* and *auto* plugins; this plugin **signs** the zones
*files*, *auto* and *file* **serve** the zones *data*.

For this plugin to work at least one Common Signing Key, (see coredns-keygen(1)) is needed. This key
(or keys) will be used to sign the entire zone. *Sign* does not support the ZSK/KSK split, nor will
it do key rollovers - it just signs.

*Sign* will:

* (Re)-sign the zone with the CSK(s) when the last time it was signed is more than a 6 days ago.
  Each zone will have some jitter (0, 3 days) applied. If the SOA signature has 14 days left before
  expiring the zone will also be resigned.
* Create signatures that have an inception of -3 hours and a expiration of +32 days for every key given.
* Add or replace *all* apex CDS/CDNSKEY records with the ones derived from the given keys. For each
  key two CDS are created one with SHA1 and another with SHA256.
* Update the SOA's serial number to the *Unix epoch* of when the signing happens. This will
  overwrite *any* previous serial number.

Thus there are two ways that dictate when a zone is signed. Normally every 6 days (plus jitter) it
will be resigned. But when a zone hasn't been regularly been resigned its signature will expire. To
prevent this *sign* will also resign the zone, if the SOA signature has only 14 days left. The
latter check is performed on startup which will mean *all* zones with expired signatures will be
resigned.

Keys are named (following BIND9): `K<name>+<alg>+<id>.key` and `K<name>+<alg>+<id>.private`.
The keys **must not** be included in your zone; they will be added by *sign*. These keys can be
generated with `coredns-keygen` or BIND9's `dnssec-keygen`. You don't have to adhere to this naming
scheme, but then you need to name your keys explicitly, see the `keys file` directive.

A generated zone is written out in a file named `db.<name>.signed` in the directory named by the
`directory` directive.

## Syntax

~~~
sign DBFILE [ZONES...] {
    keys file|directory KEY...|DIR...
    directory DIR
}
~~~

*  **DBFILE** the zone database file to read and parse. If the path is relative, the path from the
   *root* directive will be prepended to it.
*  **ZONES** zones it should be sign for. If empty, the zones from the configuration block are
   used.
* `keys` specifies the keys (there can be multiple) to sign the zone. If `file` is
   used the **KEY**'s filenames are used as is. If `directory` is used, *sign* will look in **DIR**
   for `K<name>+<alg>+<id>` files. Any metadata in these files (Activate, Publish, etc.) is
   *ignored*. These keys must also be Key Signing Keys (KSK).
*  `directory` specifies the **DIR** where CoreDNS should save zones that have been signed.
   If not given this defaults to `/var/lib/coredns`. The zones are saved under the name
   `db.<name>.signed`. If the path is relative the path from the *root* directive will be prepended
   to it.

Keys can be generated with dnssec-keygen, to create one for use in the *sign* plugin, use:
`dnssec-keygen -a ECDSAP256SHA256 -f KSK example.org`.

## Examples

Sign the `example.org` zone contained in the file `db.example.org` and write to result to
`./db.example.org.signed` to let the *file* plugin pick it up and serve it. The keys used
are read from `/etc/coredns/keys/Kexample.org.key` and `/etc/coredns/keys/Kexample.org.private`.

~~~ txt
example.org {
    file db.example.org.signed

    sign db.example.org {
        key file /etc/coredns/keys/Kexample.org
        directory .
    }
}
~~~

Running this leads to the following log output (note the timers in this example have been set to
shorter intervals).

~~~ txt
2019-07-20T15:29:08.707Z [WARNING] plugin/file: Failed to open "open db.example.org.signed: no such file or directory": trying again in 1m0s
2019-07-20T15:29:08.719Z [INFO] plugin/sign: Signing "example.org." because open db.example.org.signed: no such file or directory
2019-07-20T15:29:08.719Z [INFO] plugin/sign: Signed "example.org." with key tags "59725" in 11.670985ms, saved in "db.example.org.signed". Next: 2019-07-20T15:49:06.560Z
2019-07-20T15:30:08.711Z [INFO] plugin/file: Successfully reloaded zone "example.org." in "db.example.org.signed" with serial 1563636548
2019-07-20T15:49:08.709Z [INFO] plugin/sign: Signing "example.org." because resign was: 10m0s ago
2019-07-20T15:49:08.709Z [INFO] plugin/sign: Signed "example.org." with key tags "59725" in 2.055895ms, saved in "db.example.org.signed". Next: 2019-07-20T16:09:06.560Z
2019-07-20T15:50:08.708Z [INFO] plugin/file: Successfully reloaded zone "example.org." in "db.example.org.signed" with serial 1563637748
~~~

Or use a single zone file for *multiple* zones, note that the **ZONES** are repeated for both plugins.
Also note this outputs *multiple* signed output files. Here we use the default output directory
`/var/lib/coredns`.

~~~ txt
. {
    file /var/lib/coredns/db.example.org.signed example.org
    file /var/lib/coredns/db.example.net.signed example.net
    sign db.example.org example.org example.net {
        key directory /etc/coredns/keys
    }
}
~~~

This is the same configuration, but the zones are put in the server block, but note that you still
need to specify what file is served for what zone in the *file* plugin:

~~~ txt
example.org example.net {
    file var/lib/coredns/db.example.org.signed example.org
    file var/lib/coredns/db.example.net.signed example.net
    sign db.example.org {
        key directory /etc/coredns/keys
    }
}
~~~

Be careful to fully list the origins you want to sign, if you don't:

~~~ txt
example.org example.net {
    sign plugin/sign/testdata/db.example.org miek.org {
        key file /etc/coredns/keys/Kexample.org
    }
}
~~~

This will lead to `db.example.org` be signed *twice*, as this entire section is parsed twice because
you have specified the origins `example.org` and `example.net` in the server block.

## Also See

The DNSSEC RFCs: RFC 4033, RFC 4034 and RFC 4035. And the BCP on DNSSEC, RFC 6781. Further more the
manual pages coredns-keygen(1) and dnssec-keygen(8). And the *file* plugin's documentation.

## Bugs

`keys directory` is not implemented, nor is coredns-keygen(1). Glue records are currently signed.
