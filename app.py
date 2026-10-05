import hashlib
import requests
import streamlit as st
from zxcvbn import zxcvbn

st.set_page_config(
    page_title="Password Security Analyzer",
    page_icon="🔐",
    layout="centered"
)

st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #101827, #172554);
    color: white;
}
h1, h2, h3, p, label {
    color: white !important;
}
div.stButton > button {
    width: 100%;
    border-radius: 10px;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

st.title("🔐 Password Security Analyzer")
st.write(
    "Analyze password strength, discover weaknesses, "
    "and learn how to improve account security."
)

st.info(
    "Privacy: Your password is analyzed in this app and is not saved "
    "by this code. The optional breach check sends only the first "
    "5 characters of its SHA-1 hash to the breach-checking service."
)

password = st.text_input(
    "Enter a password to analyze",
    type="password",
    placeholder="Type a password here..."
)

show_password = st.checkbox("Show password")
if show_password and password:
    st.code(password)

if password:
    result = zxcvbn(password)
    score = result["score"]

    labels = [
        "Very weak",
        "Weak",
        "Fair",
        "Strong",
        "Very strong"
    ]

    st.subheader("Password strength")
    st.progress((score + 1) / 5)
    st.write(f"**Rating:** {labels[score]} ({score}/4)")

    st.subheader("Security details")

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Password length", len(password))

    with col2:
        st.metric("Estimated guesses", f"{result['guesses']:,}")

    crack_time = result["crack_times_display"][
        "offline_slow_hashing_1e4_per_second"
    ]

    st.write("**Illustrative offline cracking estimate:**", crack_time)

    st.caption(
        "Estimates are approximate and depend on the attack method, "
        "hardware, and password-storage security."
    )

    st.subheader("How to improve it")

    suggestions = result["feedback"]["suggestions"]
    warning = result["feedback"]["warning"]

    if warning:
        st.warning(warning)

    if suggestions:
        for suggestion in suggestions:
            st.write(f"• {suggestion}")
    elif score >= 3:
        st.success("Good work! No specific improvements were suggested.")
    else:
        st.write("Try using a longer, unique passphrase.")

    st.subheader("Password breach check")

    st.write(
        "Optionally check whether this password appears in the "
        "Have I Been Pwned Pwned Passwords database."
    )

    if st.button("Check known data breaches"):
        if not password:
            st.warning("Enter a password first.")
        else:
            try:
                sha1_hash = hashlib.sha1(
                    password.encode("utf-8")
                ).hexdigest().upper()

                prefix = sha1_hash[:5]
                suffix = sha1_hash[5:]

                response = requests.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}",
                    headers={"Add-Padding": "true"},
                    timeout=10
                )
                response.raise_for_status()

                found_count = 0

                for line in response.text.splitlines():
                    parts = line.split(":")
                    if len(parts) == 2 and parts[0] == suffix:
                        found_count = int(parts[1])
                        break

                if found_count:
                    st.error(
                        f"This password was found {found_count:,} "
                        "times in the database. Do not use it."
                    )
                else:
                    st.success(
                        "No match was found in this database. "
                        "This does not guarantee that the password "
                        "has never been exposed."
                    )

            except requests.RequestException:
                st.error(
                    "The breach service could not be reached. "
                    "Check your internet connection and try again."
                )

st.divider()

st.caption(
    "Security tip: Use a unique password for every account, "
    "consider a password manager, and enable two-factor authentication."
)