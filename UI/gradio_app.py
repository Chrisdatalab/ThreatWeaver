import gradio as gr

from UI.session import create_session
from services.analyzer import (
    analyze_file,
    run_correlations,
    build_ai_context,
)
from services.ai_analyst import (
    analyze_security_context,
    answer_security_question,
)
def analyze_uploaded_log(file_path, log_type, year, session):
    if not file_path:
        return session, "Please upload a log file.", []

    findings = analyze_file(
        file_path,
        log_type,
        int(year) if year else None
    )

    correlated = run_correlations(findings)

    context = build_ai_context(
        findings,
        correlated
    )

    report = analyze_security_context(context)

    session = session.copy()
    session["context"] = context
    session["history"] = []

    return session, report, []
def chat_with_analyst(question, session):
    if not session.get("context"):
        return session, [
            {
                "role": "assistant",
                "content": "Please analyze a log file first."
            }
        ], ""

    if not question.strip():
        return session, session["history"], ""

    history = list(session.get("history", []))

    answer = answer_security_question(
        session["context"],
        question,
        history
    )

    history.append({
        "role": "user",
        "content": question
    })

    history.append({
        "role": "assistant",
        "content": answer
    })

    session = session.copy()
    session["history"] = history

    return session, history, ""
with gr.Blocks(title="ThreatWeaver") as demo:

    session_state = gr.State(create_session())

    gr.Markdown("# ThreatWeaver")

    log_file = gr.File(
        label="Upload Log File",
        type="filepath"
    )
    log_type = gr.Dropdown(
        choices=["linux", "web"],
        label="Log Type"
    )

    year = gr.Number(
        label="Year",
        value=2026
    )

    analyze_button = gr.Button("Analyze")

    ai_report = gr.Markdown(
        label="AI Analysis"
    )

    chatbot = gr.Chatbot(
        label="ThreatWeaver Analyst",
        
    )

    question = gr.Textbox(
        label="Ask about this investigation"
    )

    send_button = gr.Button("Send")
    analyze_button.click(
        fn=analyze_uploaded_log,
        inputs=[
            log_file,
            log_type,
            year,
            session_state
        ],
        outputs=[
            session_state,
            ai_report,
            chatbot
        ]
    )
    send_button.click(
        fn=chat_with_analyst,
        inputs=[
            question,
            session_state
        ],
        outputs=[
            session_state,
            chatbot,
            question
        ]
    )

if __name__ == "__main__":
    demo.launch()