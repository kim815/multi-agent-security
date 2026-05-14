from agents.analysis_agent import AnalysisResult


def remediation_prompt(analysis: AnalysisResult, validation_feedback: str | None = None) -> str:
    feedback_block = ""
    if validation_feedback:
        feedback_block = f"\n\nVALIDATION FEEDBACK (previous attempt failed):\n{validation_feedback}\n"

    return (
        "You are a secure dependency remediation AI.\n\n"
        "TASK:\nFix vulnerable npm dependency.\n\n"
        f"DEPENDENCY:\n{analysis.dependency}\n\n"
        f"CURRENT VERSION:\n{analysis.current_version}\n\n"
        f"RECOMMENDED SAFE VERSION:\n{analysis.recommended_version}\n\n"
        f"VULNERABILITY:\n{analysis.issue_type}\n\n"
        "REQUIREMENTS:\n"
        "- Update only required dependency\n"
        "- Preserve compatibility\n"
        "- Return updated package.json dependency snippet only\n"
        "- Output must be valid JSON fragment\n"
        "\n"
        "OUTPUT:\nProvide corrected dependency block (e.g., {\"axios\": \"^1.6.0\"})."
        + feedback_block
    )
