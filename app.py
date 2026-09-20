

import streamlit as st

from sources import (
    SOURCE_REGISTRY,
    build_gemini_prompt,
    call_gemini,
    detect_ioc_type,
    parse_gemini_response,
)



st.set_page_config(page_title="ThreatLens", page_icon="🛡️", layout="centered")

VERDICT_STYLE = {
    "Safe": {"color": "#1a7f37", "emoji": "✅"},
    "Suspicious": {"color": "#b78103", "emoji": "⚠️"},
    "Malicious": {"color": "#cf222e", "emoji": "🛑"},
    "Unknown": {"color": "#57606a", "emoji": "❓"},
}


st.title("🛡️ ThreatLens")
st.caption("AI-powered defensive threat intelligence")

st.write(
    "Enter an IP address, domain, or URL below. ThreatLens gathers evidence "
    "from multiple intelligence sources and uses AI to summarize the "
    "findings -- it does not replace your own judgment or existing "
    "security tooling."
)



ioc_input = st.text_input(
    "Enter IP, domain, or URL",
    placeholder="example.com | 8.8.8.8 | https://example.com",
)

knowledge_level = st.selectbox(
    "Explanation level",
    options=["Beginner", "Intermediate", "Expert"],
    index=1,
)

analyze_clicked = st.button("Analyze Threat", type="primary")



if analyze_clicked:
    ioc = (ioc_input or "").strip()
    ioc_type = detect_ioc_type(ioc)

    if ioc_type == "invalid":
        st.error(
            "That doesn't look like a valid IP address, domain, or URL. "
            "Please check the input and try again."
        )
    else:
        st.info(f"Detected input type: **{ioc_type.upper()}**")

        results: dict[str, dict] = {}
        with st.spinner("Gathering intelligence from sources..."):
            for source_name, source_function in SOURCE_REGISTRY.items():
                results[source_name] = source_function(ioc, ioc_type)

        # --- Source status ---------------------------------------------------
        st.subheader("Source Status")
        for source_name, result in results.items():
            if result["success"]:
                st.success(f"**{source_name}**: ✓ Successfully retrieved")
            else:
                st.warning(f"**{source_name}**: ✗ Failed -- {result['error']}")

        # --- Gemini analysis ---------------------------------------------------
        st.subheader("AI Analysis")
        with st.spinner("Analyzing evidence with Gemini..."):
            prompt = build_gemini_prompt(ioc, ioc_type, knowledge_level, results)
            gemini_response = call_gemini(prompt)

        if not gemini_response["success"]:
            st.error(f"Gemini analysis unavailable: {gemini_response['error']}")
            st.info(
                "You can still review the raw source data below to make your "
                "own assessment."
            )
            analysis = None
        else:
            analysis = parse_gemini_response(gemini_response["text"])
            if analysis.get("parse_error"):
                st.warning(
                    f"Gemini's response could not be fully parsed ({analysis['parse_error']}). "
                    "Showing a safe fallback result."
                )

        # --- Results display ---------------------------------------------------
        if analysis is not None:
            verdict = analysis["verdict"]
            style = VERDICT_STYLE.get(verdict, VERDICT_STYLE["Unknown"])

            st.markdown(
                f"<h2 style='color:{style['color']};'>{style['emoji']} {verdict.upper()}</h2>",
                unsafe_allow_html=True,
            )

            st.metric("ThreatLens AI Risk Score", f"{analysis['risk_score']}/100")
            st.progress(analysis["risk_score"] / 100)

            st.markdown("**AI Summary**")
            st.write(analysis["summary"])

            st.markdown("**Key Findings**")
            if analysis["key_findings"]:
                for finding in analysis["key_findings"]:
                    st.markdown(f"- {finding}")
            else:
                st.write("No specific findings were listed.")

            st.markdown("**Recommendation**")
            st.write(analysis["recommendation"])

            st.caption(
                "The verdict and risk score above are AI-generated interpretations, "
                "not an official score from any single source. Always verify "
                "against the raw source data below."
            )

        # --- Raw source data (always shown, regardless of AI availability) -----
        st.subheader("Raw Source Data")
        for source_name, result in results.items():
            with st.expander(f"{source_name} Data"):
                if result["success"]:
                    st.json(result["data"])
                else:
                    st.write(f"No data available. Error: {result['error']}")

else:
    st.caption("Enter an indicator above and click **Analyze Threat** to begin.")
