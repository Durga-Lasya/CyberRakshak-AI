from cyberrakshak.detector import analyze_transcript

def test_high_risk_otp():
    r=analyze_transcript("I am calling from your bank. Your account will be blocked today. Share your OTP immediately.")
    assert r["score"] >= 50
    assert r["level"] in ("HIGH","CRITICAL")

def test_remote_payment_combo():
    r=analyze_transcript("Install AnyDesk and then make a UPI payment.")
    assert any(x["key"]=="sequence" for x in r["signals"])

def test_benign_reminder():
    r=analyze_transcript("Your appointment is confirmed for tomorrow at 10 AM.")
    assert r["level"]=="LOW"


def test_hindi_code_mixed_otp_scam():
    r = analyze_transcript("मैं bank से बोल रहा हूँ, आपका account आज बंद हो जाएगा। कृपया अपना OTP बताइये।")
    assert r["level"] in ("HIGH", "CRITICAL")
    assert {"authority", "urgency", "credential"}.issubset({s["key"] for s in r["signals"]})

def test_kannada_otp_scam():
    r = analyze_transcript("ನಾನು ಬ್ಯಾಂಕ್‌ನಿಂದ ಮಾತನಾಡುತ್ತಿದ್ದೇನೆ. ದಯವಿಟ್ಟು ನಿಮ್ಮ ಒಟಿಪಿ ತಿಳಿಸಿ.")
    assert "credential" in {s["key"] for s in r["signals"]}
    assert "authority" in {s["key"] for s in r["signals"]}

def test_tamil_otp_scam():
    r = analyze_transcript("வங்கியிலிருந்து பேசுகிறேன். உங்கள் OTP சொல்லுங்கள்.")
    assert "credential" in {s["key"] for s in r["signals"]}
    assert "authority" in {s["key"] for s in r["signals"]}

def test_telugu_otp_scam():
    r = analyze_transcript("బ్యాంక్ నుండి మాట్లాడుతున్నాను. మీ ఓటిపి చెప్పండి.")
    assert "credential" in {s["key"] for s in r["signals"]}
    assert "authority" in {s["key"] for s in r["signals"]}

def test_bengali_otp_scam():
    r = analyze_transcript("ব্যাংক থেকে বলছি। আপনার ওটিপি বলুন।")
    assert "credential" in {s["key"] for s in r["signals"]}
    assert "authority" in {s["key"] for s in r["signals"]}

def test_marathi_otp_scam():
    r = analyze_transcript("मी बँकेतून बोलत आहे. तुमचा ओटीपी सांगा.")
    assert "credential" in {s["key"] for s in r["signals"]}
    assert "authority" in {s["key"] for s in r["signals"]}

def test_gujarati_otp_scam():
    r = analyze_transcript("બેંકમાંથી બોલું છું. તમારો ઓટીપી કહો.")
    assert "credential" in {s["key"] for s in r["signals"]}
    assert "authority" in {s["key"] for s in r["signals"]}

def test_punjabi_otp_scam():
    r = analyze_transcript("ਬੈਂਕ ਤੋਂ ਬੋਲ ਰਿਹਾ ਹਾਂ। ਆਪਣਾ ਓਟੀਪੀ ਦੱਸੋ।")
    assert "credential" in {s["key"] for s in r["signals"]}
    assert "authority" in {s["key"] for s in r["signals"]}


def test_benign_telugu_bank_conversation_is_low_risk():
    text = (
        "నమస్తే sir. నేను మీ bank నుంచి మాట్లాడుతున్నాను. account statement గురించి "
        "information ఇవ్వడానికి call చేశాను. మీరు official bank app details check చేయొచ్చు. "
        "నేను ఈరోజు bank కి వెళ్లాను. నా account balance check చేశాను, statement కూడా "
        "download చేసుకున్నాను. మీ OTP PIN ఎవరికీ చెప్పకండి. Bank employees కూడా మీ OTP అడగకూడదు."
    )
    r = analyze_transcript(text)
    assert r["level"] == "LOW"
    assert r["score"] < 25


def test_english_safety_warning_is_not_credential_theft():
    r = analyze_transcript(
        "Never share your OTP or PIN. Bank employees should not ask for your OTP."
    )
    assert r["level"] == "LOW"
    assert "credential" not in {s["key"] for s in r["signals"]}


def test_benign_bank_visit_is_not_urgency_or_authority_scam():
    r = analyze_transcript(
        "I went to the bank today. I checked my account balance and downloaded my statement."
    )
    assert r["level"] == "LOW"
    assert not ({"urgency", "authority"} & {s["key"] for s in r["signals"]})


def test_kannada_code_mixed_otp_account_block_from_live_transcript():
    text = "ನಮಸ್ಕಾರ sir, ನಿಮ್ಮ bank account block ಆಗುತ್ತೆ. ನಿಮ್ಮ mobileಗೆ ಬಂದ OTP ಹೇಳಿ. ಇಲ್ಲಾಂದ್ರೆ ನಿಮ್ಮ bank account close ಆಗುತ್ತೆ."
    r = analyze_transcript(text)
    assert r["level"] in ("HIGH", "CRITICAL")
    assert "credential" in {s["key"] for s in r["signals"]}


def test_malayalam_code_mixed_otp_account_block_from_live_transcript():
    text = "നമസ്കാരം sir, നിങ്ങളുടെ bank account block ആകട്ടപ്പോഴാണ്. മൊബൈലിൽ വന്ന OTP പറയോ, അല്ലെങ്കിൽ account close ആക്കും."
    r = analyze_transcript(text)
    assert r["level"] in ("HIGH", "CRITICAL")
    assert "credential" in {s["key"] for s in r["signals"]}


def test_gujarati_code_mixed_otp_account_block_from_live_transcript():
    text = "નમસ્તે sir, તમારું bank account બંધ થઈ જશે. તમારા mobile પર આવેલો OTP મને કહેજો, નહીં તો account બંધ થઈ જશે."
    r = analyze_transcript(text)
    assert r["level"] in ("HIGH", "CRITICAL")
    assert "credential" in {s["key"] for s in r["signals"]}


def test_kannada_romanised_otp_request():
    r = analyze_transcript("Nimma mobile ge banda OTP heli, illandre account close agutte.")
    assert r["level"] in ("HIGH", "CRITICAL")
    assert "credential" in {s["key"] for s in r["signals"]}


def test_malayalam_romanised_otp_request():
    r = analyze_transcript("Ningalude mobile-il vanna OTP parayoo, allenkil account close aakum.")
    assert r["level"] in ("HIGH", "CRITICAL")
    assert "credential" in {s["key"] for s in r["signals"]}


def test_gujarati_romanised_otp_request():
    r = analyze_transcript("Tamara mobile par aavelo OTP mane kahjo, nahi to account bandh thai jashe.")
    assert r["level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert "credential" in {s["key"] for s in r["signals"]}


def test_romanised_protective_otp_warning_is_not_credential_theft():
    r = analyze_transcript("OTP PIN yarigu helbedi. Bank employees OTP adagakoodadu.")
    assert r["level"] == "LOW"
    assert "credential" not in {s["key"] for s in r["signals"]}
