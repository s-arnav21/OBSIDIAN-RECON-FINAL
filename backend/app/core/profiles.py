"""Scan profiles — named presets that shape a scan."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanProfile:
    name: str
    display_name: str
    description: str

    skip_skills: list[str] = field(default_factory=list)
    include_only_skills: list[str] = field(default_factory=list)
    skip_scanners: list[str] = field(default_factory=list)

    allow_exploit_skills: bool = False
    internet_available: bool = True
    dns_available: bool = True
    root_available: bool = False

    nmap_timing: str = "T4"
    nmap_min_rate: int = 500
    nmap_full_port: bool = True

    wordlist_profile: str = "default"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "skip_skills": list(self.skip_skills),
            "include_only_skills": list(self.include_only_skills),
            "skip_scanners": list(self.skip_scanners),
            "allow_exploit_skills": self.allow_exploit_skills,
            "internet_available": self.internet_available,
            "dns_available": self.dns_available,
            "root_available": self.root_available,
            "nmap_timing": self.nmap_timing,
            "nmap_min_rate": self.nmap_min_rate,
            "nmap_full_port": self.nmap_full_port,
            "wordlist_profile": self.wordlist_profile,
        }


_INTERNET_SKILLS = [
    "wayback-harvest",
    "cert-transparency",
    "subdomain-enum",
    "dns-zone-transfer",
    "reverse-ip",
    "whois-analysis",
    "email-security",
    "takeover-check",
    "origin-hunt",
]

PROFILES = {
    "vm": ScanProfile(
        name="vm",
        display_name="Vulnerable VM / Lab",
        description="Full exploit-enabled scan for VulnHub/HTB VMs on an isolated local network.",
        # Nuclei + nuclei-targeted + subdomain enumeration stay ENABLED
        # (nuclei templates are cached locally and the subdomain scanner is
        # pure-Python httpx); only purely-internet-dependent discovery skills
        # are skipped on an isolated network.
        skip_skills=[*_INTERNET_SKILLS],
        skip_scanners=[],
        allow_exploit_skills=True,
        internet_available=False,
        dns_available=False,
        wordlist_profile="vm",
    ),
    "webapp": ScanProfile(
        name="webapp",
        display_name="Web Application (internet target)",
        description="Full web recon + passive OSINT. No exploit skills.",
        allow_exploit_skills=False,
        internet_available=True,
        dns_available=True,
        nmap_full_port=False,
        wordlist_profile="webapp",
    ),
    "ctf": ScanProfile(
        name="ctf",
        display_name="CTF / HackTheBox",
        description="VM profile + root nmap OS detection + aggressive timing.",
        skip_skills=[*_INTERNET_SKILLS],
        skip_scanners=[],
        allow_exploit_skills=True,
        internet_available=False,
        dns_available=False,
        root_available=True,
        nmap_timing="T5",
        nmap_min_rate=2000,
        wordlist_profile="vm",
    ),
    "stealth": ScanProfile(
        name="stealth",
        display_name="Stealth / Low-and-slow",
        description="Reduced rate, no active exploit skills.",
        allow_exploit_skills=False,
        nmap_timing="T2",
        nmap_min_rate=50,
        nmap_full_port=False,
        wordlist_profile="default",
    ),
}


def get_profile(name: Optional[str]) -> ScanProfile:
    if not name:
        return PROFILES["webapp"]
    return PROFILES.get(name.lower().strip(), PROFILES["webapp"])


def profile_names() -> list[str]:
    return ["webapp", "vm", "ctf", "stealth"]
