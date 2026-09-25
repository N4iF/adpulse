"""Static HTML report (EN/AR) from a ScanResult. No JavaScript; printing the page is the PDF report."""

from __future__ import annotations

import re
from importlib.resources import files

from jinja2 import Environment, StrictUndefined
from markupsafe import Markup, escape

from adrules.catalog import load_catalog
from adrules.controls import ecc_view, load_subdomain
from adrules.finding import Localized, Status
from adrules.scan import ScanResult

LIMITATION = {
    "en": "This result evaluates technical AD configuration only; organizational policy/process compliance is not assessed.",
    "ar": "يقيّم هذا الناتج الإعدادات التقنية لـ Active Directory فقط، ولا يشمل الامتثال على مستوى السياسات والإجراءات التنظيمية.",
}

LABELS: dict[str, dict[str, str]] = {
    "en": {
        "title": "Active Directory security assessment",
        "to_fix": "Problems to fix", "fixed": "Fixed since the last scan", "passed": "Checks passed",
        "not_checked": "Not checked", "of": "of",
        "what_to_fix": "What to fix", "fixed_title": "Fixed since the last scan",
        "all_passed": "No problems found. All checks passed.", "no_problems": "No problems found in the checks that ran.",
        "new": "New", "open": "Still open", "resolved": "Fixed", "not_reassessed": "not re-checked in this scan",
        "found": "What we found", "why": "Why it matters", "fix": "How to fix", "details": "Details",
        "account": "Account", "setting": "Setting", "current": "Current value", "expected": "Required", "last_seen": "Last seen value",
        "check_id": "Check", "object": "Object", "ecc": "NCA ECC-2:2024", "attack": "MITRE ATT&CK", "source": "Source",
        "all_checks": "All checks", "check": "Check", "status": "Result", "reason": "Note",
        "history": "Scan history", "date": "Date", "h_problems": "Problems", "h_new": "New", "h_open": "Still open",
        "h_fixed": "Fixed",
        "grc_open": "NCA ECC-2:2024 view — for governance, risk and audit teams",
        "history_note": "The scan history above is a dated record of periodic assessment; it supports 2-2-3-5 (periodic review of identities and access rights).",
        "ecc_title": "NCA ECC-2:2024 technical evidence", "subdomain": "Subdomain", "control": "Control",
        "ev_status": "Technical evidence", "checks_col": "Checks", "note": "Note", "planned": "Planned checks",
    },
    "ar": {
        "title": "تقييم أمن Active Directory",
        "to_fix": "مشكلات تحتاج إلى معالجة", "fixed": "مُعالَجة منذ الفحص السابق", "passed": "فحوصات ناجحة",
        "not_checked": "لم تُفحص", "of": "من",
        "what_to_fix": "ما يجب إصلاحه", "fixed_title": "ما عولج منذ الفحص السابق",
        "all_passed": "لا توجد مشكلات. نجحت جميع الفحوصات.", "no_problems": "لا توجد مشكلات في الفحوصات التي نُفِّذت.",
        "new": "جديدة", "open": "ما زالت مفتوحة", "resolved": "مُعالَجة", "not_reassessed": "لم يُعَد فحصها في عملية الفحص هذه",
        "found": "ما وجدناه", "why": "الأهمية", "fix": "طريقة المعالجة", "details": "تفاصيل",
        "account": "الحساب", "setting": "الإعداد", "current": "القيمة الحالية", "expected": "المطلوب", "last_seen": "آخر قيمة",
        "check_id": "الفحص", "object": "العنصر", "ecc": "ECC-2:2024", "attack": "MITRE ATT&CK", "source": "المصدر",
        "all_checks": "جميع الفحوصات", "check": "الفحص", "status": "النتيجة", "reason": "ملاحظة",
        "history": "سجل عمليات الفحص", "date": "التاريخ", "h_problems": "مشكلات", "h_new": "جديدة", "h_open": "مفتوحة",
        "h_fixed": "مُعالَجة",
        "grc_open": "عرض الضوابط الأساسية للأمن السيبراني ECC-2:2024 — لفرق الحوكمة والمخاطر والتدقيق",
        "history_note": "سجل عمليات الفحص أعلاه توثيق مؤرَّخ للتقييم الدوري، يدعم الضابط 2-2-3-5 (المراجعة الدورية لهويات الدخول والصلاحيات).",
        "ecc_title": "دليل تقني للضوابط الأساسية للأمن السيبراني ECC-2:2024", "subdomain": "المكوّن الفرعي",
        "control": "الضابط", "ev_status": "الدليل التقني", "checks_col": "الفحوصات", "note": "ملاحظة",
        "planned": "فحوصات مخطط لها",
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
EVIDENCE = {
    "en": {"technical_evidence_pass": "Pass", "technical_evidence_fail": "Fail", "not_assessed": "Not assessed"},
    "ar": {"technical_evidence_pass": "ناجح", "technical_evidence_fail": "فاشل", "not_assessed": "لم يُقيَّم"},
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


# A run of Latin text (a GPMC path, a setting name, a PowerShell command) inside Arabic text. Inside a run,
# also the punctuation an account name may hold; ';' stays out, so two commands stay two runs.
_LTR_RUN = re.compile(r"\"?(?:[A-Za-z0-9][A-Za-z0-9 <>.,:/'_$=\-()&!#%@^`{}~‘-‛]*[A-Za-z0-9]|[A-Za-z0-9])\"?")  # quotes stay with their words


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


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def render_report(scan: ScanResult, history: list[ScanResult], lang: str = "en") -> str:
    if lang not in LABELS:
        raise ValueError(f"unsupported language {lang!r}")
    titles: dict[str, Localized] = {r.meta.id: r.meta.title for r in load_catalog()}
    env = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True, undefined=StrictUndefined)
    env.filters["bidi"] = isolate_ltr if lang == "ar" else escape
    env.filters["reason"] = lambda reason: reason_text(reason, lang)
    template = env.from_string(files("adrules").joinpath("templates/report.html.j2").read_text(encoding="utf-8"))
    to_fix = sorted((e for e in scan.lifecycle if e.state != "resolved"), key=lambda e: SEVERITY_ORDER[e.finding.severity.value])
    return template.render(
        scan=scan, history=history[-10:], lang=lang, direction="rtl" if lang == "ar" else "ltr",
        t=LABELS[lang], limitation=LIMITATION[lang], mode_label=MODE[lang].get(scan.mode, scan.mode),
        severity=SEVERITY[lang], status=STATUS[lang], evidence=EVIDENCE[lang], titles=titles,
        controls=ecc_view(scan.results), subdomain=load_subdomain(),
        to_fix=to_fix, fixed=[e for e in scan.lifecycle if e.state == "resolved"],
        passed=sum(1 for r in scan.results if r.status is Status.PASS),
        not_checked=len(scan.results) - scan.assessed(),
        all_passed=bool(scan.results) and all(r.status is Status.PASS for r in scan.results),
    )
