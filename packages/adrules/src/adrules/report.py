"""Static HTML report (EN/AR) from a ScanResult. No JavaScript; printing the page is the PDF report."""

from __future__ import annotations

import re
from importlib.resources import files

from jinja2 import Environment, StrictUndefined
from markupsafe import Markup, escape

from adrules.catalog import load_catalog
from adrules.finding import Localized, Status
from adrules.scan import ScanResult

LIMITATION = {
    "en": "This result evaluates technical AD configuration only; organizational policy/process compliance is not assessed.",
    "ar": "يقيّم هذا الناتج الإعدادات التقنية لـ Active Directory فقط، ولا يشمل الامتثال على مستوى السياسات والإجراءات التنظيمية.",
}

LABELS: dict[str, dict[str, str]] = {
    "en": {
        "title": "AD security control assessment", "checks": "Checks run", "failed": "Failed", "new": "New",
        "resolved": "Resolved", "open": "Open", "not_assessed": "Not assessed", "findings": "Findings", "checks_title": "Checks",
        "history": "Scan history", "all_passed": "No findings. All checks passed.", "no_findings": "No findings.",
        "assessed": "Checks assessed", "of": "of", "why": "Why it matters", "fix": "How to fix",
        "ecc": "NCA ECC-2:2024 technical evidence", "attack": "MITRE ATT&CK", "state": "State", "status": "Status",
        "severity": "Severity", "rule": "Rule", "check": "Check", "reason": "Reason", "evidence": "Evidence",
        "evidence_source": "Evidence source", "not_reassessed": "not re-assessed in this scan", "date": "Date",
        "setting": "Setting", "current": "Current", "expected": "Expected", "last_seen": "Last seen",
        "object": "Object",
        "history_note": "Evidence of periodic review of identities and access rights (NCA ECC-2:2024 2-2-3-5, technical evidence).",
    },
    "ar": {
        "title": "تقييم ضوابط أمن Active Directory", "checks": "الفحوصات المنفذة", "failed": "فاشلة",
        "new": "جديدة", "resolved": "مُعالَجة", "open": "مفتوحة", "not_assessed": "لم تُقيَّم", "findings": "النتائج",
        "checks_title": "الفحوصات", "history": "سجل عمليات الفحص", "all_passed": "لا توجد نتائج. نجحت جميع الفحوصات.", "no_findings": "لا توجد نتائج.",
        "assessed": "الفحوصات المُقيَّمة", "of": "من", "why": "الأهمية", "fix": "طريقة المعالجة",
        "ecc": "دليل تقني للضوابط الأساسية للأمن السيبراني ECC-2:2024", "attack": "MITRE ATT&CK", "state": "الحالة",
        "status": "النتيجة", "severity": "الخطورة", "rule": "القاعدة", "check": "الفحص", "reason": "السبب",
        "evidence": "الدليل", "evidence_source": "مصدر الدليل", "not_reassessed": "لم يُعَد تقييمها في عملية الفحص هذه",
        "date": "التاريخ", "setting": "الإعداد", "current": "القيمة الحالية", "expected": "المطلوب",
        "last_seen": "آخر قيمة", "object": "العنصر",
        "history_note": "دليل تقني على المراجعة الدورية لهويات الدخول والصلاحيات (الضابط 2-2-3-5 من ECC-2:2024).",
    },
}

MODE = {
    "en": {"standard": "Standard-user assessment", "privileged": "Privileged assessment"},
    "ar": {"standard": "تقييم بصلاحيات مستخدم عادي", "privileged": "تقييم بصلاحيات مرتفعة"},
}
SEVERITY = {
    "en": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"},
    "ar": {"critical": "حرجة", "high": "عالية", "medium": "متوسطة", "low": "منخفضة"},
}
STATUS = {
    "en": {"pass": "Passed", "fail": "Failed", "not_assessed": "Not assessed", "needs_elevated": "Needs elevated privileges"},
    "ar": {"pass": "ناجح", "fail": "فاشل", "not_assessed": "لم يُقيَّم", "needs_elevated": "يتطلب صلاحيات مرتفعة"},
}


# Arabic for the runner's reason sentences (CheckResult.reason stays English in the JSON).
_REASONS_AR = [
    (re.compile(r"^coverage (.+) is none$"), "لم تُجمع بيانات: {0}"),
    (re.compile(r"^rule needs privileged collection$"), "يتطلب جمع البيانات بصلاحيات مرتفعة"),
    (re.compile(r"^(\w+) was not collected from the domain object$"), "لم يُقرأ {0} من كائن المجال"),
]


def reason_text(reason: str | None, lang: str) -> str:
    if not reason or lang != "ar":
        return reason or ""
    for pattern, arabic in _REASONS_AR:
        match = pattern.match(reason)
        if match:
            return arabic.format(*match.groups())
    return reason


# A run of Latin text (a GPMC path, a setting name, a number) inside Arabic text.
_LTR_RUN = re.compile(r"[A-Za-z0-9][A-Za-z0-9 >.,:/'_\-]*[A-Za-z0-9]|[A-Za-z0-9]")


def isolate_ltr(text: str) -> Markup:
    """Escape `text` and wrap each Latin run in <bdi dir="ltr"> so it keeps its order inside RTL text."""
    parts: list[str] = []
    pos = 0
    for match in _LTR_RUN.finditer(text):
        parts.append(escape(text[pos:match.start()]))
        parts.append(Markup('<bdi dir="ltr">') + escape(match.group()) + Markup("</bdi>"))
        pos = match.end()
    parts.append(escape(text[pos:]))
    return Markup("").join(parts)


def render_report(scan: ScanResult, history: list[ScanResult], lang: str = "en") -> str:
    if lang not in LABELS:
        raise ValueError(f"unsupported language {lang!r}")
    titles: dict[str, Localized] = {r.meta.id: r.meta.title for r in load_catalog()}
    env = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True, undefined=StrictUndefined)
    env.filters["bidi"] = isolate_ltr if lang == "ar" else escape
    env.filters["reason"] = lambda reason: reason_text(reason, lang)
    template = env.from_string(files("adrules").joinpath("templates/report.html.j2").read_text(encoding="utf-8"))
    return template.render(
        scan=scan, history=history[-10:], lang=lang, direction="rtl" if lang == "ar" else "ltr",
        t=LABELS[lang], limitation=LIMITATION[lang], mode_label=MODE[lang].get(scan.mode, scan.mode),
        severity=SEVERITY[lang], status=STATUS[lang], titles=titles,
        all_passed=bool(scan.results) and all(r.status is Status.PASS for r in scan.results),
    )
