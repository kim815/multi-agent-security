from agents.analysis_agent import AnalysisResult


def remediation_prompt(analysis: AnalysisResult, validation_feedback: str | None = None) -> str:
    feedback_block = ""
    if validation_feedback:
        feedback_block = f"\n\nVALIDATION FEEDBACK (previous attempt failed):\n{validation_feedback}\n"

    target = "npm" if analysis.ecosystem == "npm" else "python"

    return (
        "You are a secure dependency remediation AI.\n\n"
        f"TASK:\nFix vulnerable {target} dependency.\n\n"
        f"DEPENDENCY:\n{analysis.dependency}\n\n"
        f"CURRENT VERSION:\n{analysis.current_version}\n\n"
        f"RECOMMENDED SAFE VERSION:\n{analysis.recommended_version}\n\n"
        f"VULNERABILITY:\n{analysis.issue_type}\n\n"
        "REQUIREMENTS:\n"
        "- Update only required dependency\n"
        "- Preserve compatibility\n"
        "- Return ONLY a JSON object mapping dependency name to new version specifier\n"
        "- Output must be a valid JSON object\n"
        "\n"
        "OUTPUT:\nProvide corrected dependency version mapping (e.g., {\"axios\": \"^1.6.0\"} or {\"requests\": \"==2.31.0\"})."
        + feedback_block
    )
