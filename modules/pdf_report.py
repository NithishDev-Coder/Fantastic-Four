from io import BytesIO

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)


def generate_pdf(report):
    """
    Generate a PDF report from the ReconGuard scan results.
    Returns a BytesIO object.
    """

    buffer = BytesIO()

    doc = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()

    elements = []

    # ----------------------------
    # Title
    # ----------------------------

    elements.append(
        Paragraph("<b>ReconGuard Security Report</b>", styles["Title"])
    )

    elements.append(Spacer(1, 20))

    # ----------------------------
    # Target
    # ----------------------------

    elements.append(
        Paragraph(f"<b>Target:</b> {report['target']}", styles["Heading2"])
    )

    elements.append(
        Paragraph(
            f"<b>Generated:</b> {report['generated_at']}",
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 20))

    # ----------------------------
    # Risk Score
    # ----------------------------

    elements.append(
        Paragraph("<b>Risk Assessment</b>", styles["Heading2"])
    )

    elements.append(
        Paragraph(
            f"Risk Score: {report['risk']['score']} / 100",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"Risk Rating: {report['risk']['rating']}",
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 20))

    # ----------------------------
    # Summary
    # ----------------------------

    elements.append(
        Paragraph("<b>Summary</b>", styles["Heading2"])
    )

    summary = report["summary"]

    elements.append(
        Paragraph(
            f"Subdomains: {summary['subdomains_found']}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"Open Ports: {summary['open_ports_found']}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"Technologies: {summary['technologies_detected']}",
            styles["Normal"]
        )
    )

    elements.append(
        Paragraph(
            f"Exposed Panels: {summary['exposed_panels_found']}",
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 20))

    # ----------------------------
    # Findings
    # ----------------------------

    elements.append(
        Paragraph("<b>Security Findings</b>", styles["Heading2"])
    )

    for finding in report["risk"]["findings"]:

        elements.append(

            Paragraph(

                f"<b>{finding['severity'].upper()}</b> - {finding['title']}",

                styles["Normal"]

            )

        )

        elements.append(

            Paragraph(

                finding["detail"],

                styles["Normal"]

            )

        )

        elements.append(Spacer(1, 8))

    doc.build(elements)

    buffer.seek(0)

    return buffer