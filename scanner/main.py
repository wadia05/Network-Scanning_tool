# scanner/main.py
# Orchestrateur principal du scan réseau avec output colorisé
# PFE Cybersécurité — ABIED Youssef / EL-BARAZI Meriem

from __future__ import annotations

import sys

# Coloration — fallback si colorama non disponible
try:
    from colorama import Fore, Back, Style, init

    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class Fore:
        RED = YELLOW = GREEN = BLUE = CYAN = WHITE = ""

    class Back:
        RED = YELLOW = GREEN = ""

    class Style:
        BRIGHT = RESET_ALL = ""


# Core modules
from .core.arp_scan import get_local_network
from .core.port_scan import scan_all_ports, COMMON_PORTS
from .fingerprint.mac_lookup import enrich_devices as mac_lookup_enrich
from .fingerprint.tcp_fingerprint import enrich_devices as tcp_enrich
from .fingerprint.dhcp_fingerprint import enrich_devices as dhcp_enrich
from .fingerprint.http_banner import enrich_devices as http_enrich
from .fingerprint.os_classifier import enrich_devices as classifier_enrich
from .models import Device, ScanResult
from .storage import init_db, save_scan, list_scans

# ─────────────────────────────────────────────
# Couleurs et formatage
# ─────────────────────────────────────────────


def _bold(text: str) -> str:
    """Texte en gras."""
    if HAS_COLOR:
        return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"
    return text


def _success(text: str) -> str:
    """Texte en vert (succès)."""
    if HAS_COLOR:
        return f"{Fore.GREEN}{text}{Fore.RESET}"
    return text


def _warning(text: str) -> str:
    """Texte en jaune (avertissement)."""
    if HAS_COLOR:
        return f"{Fore.YELLOW}{text}{Fore.RESET}"
    return text


def _error(text: str) -> str:
    """Texte en rouge (erreur)."""
    if HAS_COLOR:
        return f"{Fore.RED}{text}{Fore.RESET}"
    return text


def _info(text: str) -> str:
    """Texte en cyan (info)."""
    if HAS_COLOR:
        return f"{Fore.CYAN}{text}{Fore.RESET}"
    return text


def _header(text: str) -> str:
    """En-tête avec fond."""
    if HAS_COLOR:
        return f"\n{Back.BLUE}{Fore.WHITE}{Style.BRIGHT} {text} {Style.RESET_ALL}\n"
    return f"\n{'='*len(text)}\n{text}\n{'='*len(text)}\n"


# ─────────────────────────────────────────────
# Pipeline de scan
# ─────────────────────────────────────────────


def run_scan(
    network: str | None = None,
    port_timeout: float = 0.5,
    resolve_hostnames: bool = False,
    save_to_db: bool = True,
) -> ScanResult:
    """
    Lance un scan réseau complet avec orchestration.

    Pipeline :
      1. Auto-détection du réseau (ou usage du paramètre)
      2. ARP scan → découverte des hôtes
      3. MAC OUI lookup → vendor identification
      4. Port scan → services sur les hôtes
      5. TCP fingerprinting → analyse stack TCP/IP
      6. DHCP fingerprinting → comportement DHCP
      7. HTTP banner grabbing → headers web
      8. OS classification → verdict final
      9. Sauvegarde en BD
     10. Rapport résumé

    Args:
        network:           Plage CIDR (ex: "192.168.1.0/24"). Auto si None.
        port_timeout:      Timeout pour scan de ports (secondes).
        resolve_hostnames: Si True, résout DNS inverse (plus lent).
        save_to_db:        Si True, persiste en SQLite.

    Returns:
        ScanResult avec tous les Device enrichis.
    """
    print(_header("🔍 NETWORK SCANNER — Cybersecurity Scan Pipeline 🔍"))

    # ─────────────────────────────────────────────────────
    # 1. Détection réseau
    # ─────────────────────────────────────────────────────
    print(_info("[*] Étape 1 : Détection du réseau local ..."))
    try:
        if network is None:
            network = get_local_network()
            print(_success(f"    ✓ Réseau détecté : {network}"))
        else:
            print(_success(f"    ✓ Réseau spécifié : {network}"))
    except RuntimeError as e:
        print(_error(f"    ✗ Erreur : {e}"))
        return ScanResult(network="unknown")

    # ─────────────────────────────────────────────────────
    # 2. ARP scan
    # ─────────────────────────────────────────────────────
    print(_info(f"\n[*] Étape 2 : Scan ARP sur {network} ..."))
    try:
        devices = arp_scan(network=network, resolve_hostnames=resolve_hostnames)
        if not devices:
            print(_warning("    ⚠ Aucun hôte découvert. Vérifiez le réseau."))
            return ScanResult(network=network)
        print(_success(f"    ✓ {len(devices)} hôte(s) découvert(s)"))
    except PermissionError as e:
        print(_error(f"    ✗ Permission refusée : {e}"))
        print(_warning("    → Lancez avec sudo ou vérifiez les droits CAP_NET_RAW"))
        return ScanResult(network=network)
    except Exception as e:
        print(_error(f"    ✗ Erreur ARP : {e}"))
        return ScanResult(network=network)

    # ─────────────────────────────────────────────────────
    # 3. MAC OUI lookup
    # ─────────────────────────────────────────────────────
    print(_info(f"\n[*] Étape 3 : MAC OUI lookup ..."))
    try:
        devices = mac_lookup_enrich(devices)
        print(_success(f"    ✓ {len(devices)} hôte(s) enrichi(s) avec vendor"))
    except Exception as e:
        print(_warning(f"    ⚠ Erreur MAC lookup (non bloquant) : {e}"))

    # ─────────────────────────────────────────────────────
    # 4. Port scan
    # ─────────────────────────────────────────────────────
    print(_info(f"\n[*] Étape 4 : Scan des ports ..."))
    try:
        devices = scan_all_ports(
            devices=devices,
            ports=list(COMMON_PORTS.keys()),
            timeout=port_timeout,
            max_workers=50,
            only_open=True,
        )
        total_open = sum(d.open_ports_count for d in devices)
        print(_success(f"    ✓ Scan terminé : {total_open} port(s) ouvert(s) au total"))
    except Exception as e:
        print(_warning(f"    ⚠ Erreur port scan (non bloquant) : {e}"))

    # ─────────────────────────────────────────────────────
    # 5. TCP fingerprinting
    # ─────────────────────────────────────────────────────
    print(_info(f"\n[*] Étape 5 : TCP fingerprinting ..."))
    try:
        devices = tcp_enrich(devices)
        print(_success(f"    ✓ TCP fingerprinting terminé"))
    except Exception as e:
        print(_warning(f"    ⚠ Erreur TCP fingerprint (non bloquant) : {e}"))

    # ─────────────────────────────────────────────────────
    # 6. DHCP fingerprinting (passif)
    # ─────────────────────────────────────────────────────
    print(_info(f"\n[*] Étape 6 : DHCP fingerprinting (passif, 5s) ..."))
    try:
        # DHCP fingerprinting optionnel — à décommenter si réseau bien configuré
        # devices = dhcp_enrich(devices, timeout=5)
        print(_warning("    ⚠ DHCP fingerprinting désactivé (optionnel)"))
    except Exception as e:
        print(_warning(f"    ⚠ Erreur DHCP (non bloquant) : {e}"))

    # ─────────────────────────────────────────────────────
    # 7. HTTP banner grabbing
    # ─────────────────────────────────────────────────────
    print(_info(f"\n[*] Étape 7 : HTTP banner grabbing ..."))
    try:
        devices = http_enrich(devices, max_workers=10)
        print(_success(f"    ✓ HTTP banner grabbing terminé"))
    except Exception as e:
        print(_warning(f"    ⚠ Erreur HTTP banner (non bloquant) : {e}"))

    # ─────────────────────────────────────────────────────
    # 8. OS classification (final)
    # ─────────────────────────────────────────────────────
    print(_info(f"\n[*] Étape 8 : Classification OS finale ..."))
    try:
        devices = classifier_enrich(devices)
        print(_success(f"    ✓ Classification OS terminée"))
    except Exception as e:
        print(_warning(f"    ⚠ Erreur classification (non bloquant) : {e}"))

    # ─────────────────────────────────────────────────────
    # 9. Création du résultat
    # ─────────────────────────────────────────────────────
    result = ScanResult(network=network, devices=devices)

    # ─────────────────────────────────────────────────────
    # 10. Sauvegarde en BD
    # ─────────────────────────────────────────────────────
    if save_to_db:
        print(_info(f"\n[*] Étape 9 : Sauvegarde en base de données ..."))
        try:
            init_db()
            scan_id = save_scan(result)
            print(_success(f"    ✓ Résultat sauvegardé — Scan ID: {scan_id}"))
        except Exception as e:
            print(_warning(f"    ⚠ Erreur BD (non bloquant) : {e}"))

    # ─────────────────────────────────────────────────────
    # 11. Rapport résumé
    # ─────────────────────────────────────────────────────
    print_scan_summary(result)

    return result


# ─────────────────────────────────────────────
# Rapports et affichage
# ─────────────────────────────────────────────


def print_scan_summary(result: ScanResult) -> None:
    """Affiche un résumé colorisé du scan."""
    print(_header("📊 RÉSUMÉ DU SCAN 📊"))

    print(f"  Réseau         : {_bold(result.network)}")
    print(f"  Timestamp      : {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Hôtes découverts: {_bold(str(result.total_hosts))}")
    print()

    if not result.devices:
        print(_warning("  ⚠ Aucun hôte découvert."))
        return

    # Tableau d'hôtes
    print(
        f"  {_bold('IP'):16} | {_bold('MAC'):18} | {_bold('Hostname'):20} | {_bold('OS'):15} | {_bold('Ports')}"
    )
    print("  " + "─" * 100)

    for device in sorted(result.devices, key=lambda d: d.ip):
        ip = device.ip
        mac = device.mac
        hostname = (device.hostname if device.hostname != "unknown" else "N/A")[:20]

        # OS avec couleur selon confidence
        if device.fingerprint:
            os_str = device.fingerprint.os_family.value
            conf = device.fingerprint.confidence
            if conf >= 0.8:
                os_str = _success(f"{os_str} ({conf:.0%})")
            elif conf >= 0.5:
                os_str = _warning(f"{os_str} ({conf:.0%})")
            else:
                os_str = f"{os_str} ({conf:.0%})"
        else:
            os_str = _warning("Unknown (0%)")

        # Ports ouverts
        open_ports = [p.number for p in device.get_open_ports()]
        ports_str = ", ".join(str(p) for p in open_ports[:5])
        if len(open_ports) > 5:
            ports_str += f", +{len(open_ports) - 5}"
        if not open_ports:
            ports_str = _warning("(none)")

        print(
            f"  {_info(ip):16} | {mac:18} | {hostname:20} | {os_str:15} | {ports_str}"
        )

    # Statistiques
    print()
    print(f"  {_bold('Statistiques')} :")
    open_ports_total = sum(d.open_ports_count for d in result.devices)
    devices_with_os = sum(
        1
        for d in result.devices
        if d.fingerprint and d.fingerprint.os_family.value != "Unknown"
    )
    print(
        f"    • Hôtes avec OS identifié  : {_success(str(devices_with_os))} / {result.total_hosts}"
    )
    print(f"    • Ports ouverts au total   : {_warning(str(open_ports_total))}")
    print(
        f"    • Services détectés        : {len(set(p.service for d in result.devices for p in d.get_open_ports()))}"
    )

    # Top services
    services = {}
    for device in result.devices:
        for port in device.get_open_ports():
            services[port.service] = services.get(port.service, 0) + 1
    if services:
        print(
            f"    • Services courants        : {', '.join(f'{svc} ({cnt})' for svc, cnt in sorted(services.items(), key=lambda x: -x[1])[:5])}"
        )

    # Top OS
    os_families = {}
    for device in result.devices:
        if device.fingerprint:
            os = device.fingerprint.os_family.value
            os_families[os] = os_families.get(os, 0) + 1
    if os_families:
        print(
            f"    • OS détectés              : {', '.join(f'{os} ({cnt})' for os, cnt in sorted(os_families.items(), key=lambda x: -x[1])[:5])}"
        )

    print()
    print(_success("✓ Scan terminé avec succès."))


def list_all_scans() -> None:
    """Affiche la liste des scans précédents."""
    print(_header("📜 SCANS PRÉCÉDENTS 📜"))
    try:
        init_db()
        scans = list_scans()
        if not scans:
            print(_warning("  Aucun scan enregistré."))
            return

        for scan in scans:
            print(
                f"  {_info(scan['scan_id'])} | {scan['network']:16} | {scan['timestamp']} | {scan['total_hosts']} hôte(s)"
            )
    except Exception as e:
        print(_error(f"  Erreur : {e}"))


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────


def main():
    """Point d'entrée principal."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Network Scanner — Cybersecurity Fingerprinting & Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                              # Auto-détecte le réseau
  python main.py --network 192.168.1.0/24     # Scanne le réseau spécifié
  python main.py --list                       # Liste les anciens scans
        """,
    )
    parser.add_argument(
        "--network",
        type=str,
        default=None,
        help="Plage CIDR à scanner (ex: 192.168.1.0/24). Auto si non spécifié.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Timeout pour le scan de ports en secondes (défaut: 0.5).",
    )
    parser.add_argument(
        "--resolve-hostnames",
        action="store_true",
        help="Résout les hostnames via DNS inverse (plus lent).",
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="N'enregistre pas le scan en base de données.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Liste les scans précédents et quitte.",
    )

    args = parser.parse_args()

    if args.list:
        list_all_scans()
        return

    # Lance le scan
    try:
        start = time.time()
        result = run_scan(
            network=args.network,
            port_timeout=args.timeout,
            resolve_hostnames=args.resolve_hostnames,
            save_to_db=not args.no_db,
        )
        elapsed = time.time() - start
        print(_info(f"\n⏱ Scan complété en {elapsed:.1f}s"))
    except KeyboardInterrupt:
        print(_error("\n\n✗ Scan annulé par l'utilisateur."))
        sys.exit(1)
    except Exception as e:
        print(_error(f"\n✗ Erreur fatale : {e}"))
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
