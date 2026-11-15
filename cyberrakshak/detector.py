"""Explainable multilingual scam-risk heuristics.

These deterministic rules are a prototype, not a trained classifier. They cover
common scam wording in major Indian languages and code-mixed speech. Scores are
risk indicators, not calibrated probabilities.
"""
import re
import unicodedata

# Each category is scored once per transcript to reduce repetition inflation.
PATTERNS = [
    ("credential", "Credential / OTP request", 35, [
        r"\b(?:otp|one[\s-]?time password|pin|cvv|password|passcode|verification code)\b[^\n.!?;।॥]{0,100}\b(?:share|tell|send|read|give|confirm|provide|enter)\b",
        r"\b(?:share|tell|send|read|give|provide)\b[^\n.!?;।॥]{0,70}\b(?:otp|pin|cvv|password|passcode)\b",
        r"(?:ओटीपी|ओटिपी|otp|पिन|पासवर्ड|गुप्त कोड)[^\n.!?;।॥]{0,65}(?:बताइए|बताइये|बताओ|दीजिए|दीजिये|भेजिए|शेयर|दें|दो)",
        r"(?:बताइए|बताइये|बताओ|दीजिए|दीजिये|भेजिए|शेयर करें)[^\n.!?;।॥]{0,55}(?:ओटीपी|ओटिपी|पिन|पासवर्ड)",
        r"(?:ಒಟಿಪಿ|ಓಟಿಪಿ|ಪಿನ್|ಗುಪ್ತ\s*ಸಂಖ್ಯೆ)[^\n.!?;।॥]{0,55}(?:ಹೇಳಿ|ತಿಳಿಸಿ|ಕಳುಹಿಸಿ|ಕೊಡಿ)",
        r"(?:otp|pin|கடவுச்சொல்|ரகசிய\s*எண்)[^\n.!?;।॥]{0,55}(?:சொல்லுங்கள்|பகிருங்கள்|அனுப்புங்கள்|கொடுங்கள்)",
        r"(?:ఓటిపి|otp|పిన్|పాస్‌వర్డ్)[^\n.!?;।॥]{0,55}(?:చెప్పండి|పంపండి|ఇవ్వండి|షేర్)",
        r"(?:ഒടിപി|otp|പിൻ|പാസ്‌വേഡ്)[^\n.!?;।॥]{0,55}(?:പറയൂ|പങ്കിടൂ|അയയ്ക്കൂ|നൽകൂ)",
        r"(?:ওটিপি|otp|পিন|পাসওয়ার্ড)[^\n.!?;।॥]{0,55}(?:বলুন|দিন|পাঠান|শেয়ার)",
        r"(?:ओटीपी|otp|पिन|पासवर्ड)[^\n.!?;।॥]{0,55}(?:सांगा|द्या|पाठवा|शेअर)",
        r"(?:ઓટીપી|otp|પિન|પાસવર્ડ)[^\n.!?;।॥]{0,55}(?:કહો|આપો|મોકલો|શેર)",
        r"(?:ਓਟੀਪੀ|otp|ਪਿੰਨ|ਪਾਸਵਰਡ)[^\n.!?;।॥]{0,55}(?:ਦੱਸੋ|ਭੇਜੋ|ਸਾਂਝਾ ਕਰੋ)",
        r"(?:ଓଟିପି|otp|ପିନ୍|ପାସୱାର୍ଡ)[^\n.!?;।॥]{0,55}(?:କୁହନ୍ତୁ|ଦିଅନ୍ତୁ|ପଠାନ୍ତୁ)",
        # Common Roman-script Hinglish and regional code-mix
        r"\b(?:otp|pin|password|cvv)\b[^\n.!?;।॥]{0,70}\b(?:batao|bataye|batayiye|bolo|boliye|bhejo|bhejiye|share karo|de do|dijiye)\b",
        r"\b(?:batao|bataye|batayiye|bhejo|bhejiye|share karo|de do|dijiye)\b[^\n.!?;।॥]{0,60}\b(?:otp|pin|password|cvv)\b",
    ]),
    ("authority", "Authority or financial-institution claim", 12, [
        r"\b(?:bank|rbi|police|cyber crime|income tax|customs|government|electricity board|telecom department)\b",
        r"(?:बैंक|आरबीआई|पुलिस|साइबर क्राइम|आयकर विभाग|सरकार)",
        r"(?:ಬ್ಯಾಂಕ್|ಆರ್‌ಬಿಐ|ಪೊಲೀಸ್|ಸೈಬರ್\s*ಕ್ರೈಂ)",
        r"(?:வங்கி|ரிசர்வ்\s*வங்கி|காவல்துறை|சைபர்\s*குற்றம்)",
        r"(?:బ్యాంక్|ఆర్బిఐ|పోలీసు|సైబర్\s*క్రైమ్)",
        r"(?:ബാങ്ക്|ആർബിഐ|പോലീസ്|സൈബർ\s*ക്രൈം)",
        r"(?:ব্যাংক|রিজার্ভ\s*ব্যাংক|পুলিশ|সাইবার\s*অপরাধ)",
        r"(?:बँक|रिझर्व्ह\s*बँक|पोलीस|सायबर\s*गुन्हे)",
        r"(?:બેંક|રિઝર્વ\s*બેંક|પોલીસ|સાયબર\s*ગુનો)",
        r"(?:ਬੈਂਕ|ਰਿਜ਼ਰਵ\s*ਬੈਂਕ|ਪੁਲਿਸ|ਸਾਈਬਰ)",
        r"(?:ବ୍ୟାଙ୍କ|ରିଜର୍ଭ\s*ବ୍ୟାଙ୍କ|ପୋଲିସ|ସାଇବର)",
        r"\b(?:bank se|bank nundi|bank inda|bankil ninn|bank theke|bank kadun)\b",
    ]),
    ("urgency", "Urgency, threat or pressure", 18, [
        r"\b(?:immediately|urgent|right now|within \d+ minutes|final warning|last chance|will be blocked|will be suspended|face arrest|legal action)\b",
        r"(?:तुरंत|तत्काल|खाता[^\n.!?;।॥]{0,20}(?:बंद|ब्लॉक)|बंद\s*हो\s*जाएगा|निलंबित|गिरफ्तार|आखिरी\s*चेतावनी)",
        r"(?:ತಕ್ಷಣ|ಈಗಲೇ|ಖಾತೆ[^\n.!?;।॥]{0,20}(?:ಮುಚ್ಚು|ನಿಲ್ಲಿಸು)|ಮುಚ್ಚಲಾಗುತ್ತದೆ|ಬಂಧನ)",
        r"(?:உடனே|இப்போதே|கணக்கு[^\n.!?;।॥]{0,20}(?:முடக்க|நிறுத்த)|முடக்கப்படும்|கைது)",
        r"(?:వెంటనే|ఇప్పుడే|ఖాతా[^\n.!?;।॥]{0,20}(?:మూసి|బ్లాక్)|నిలిపివేయబడుతుంది|అరెస్ట్)",
        r"(?:ഉടൻ|ഇപ്പോൾ|അക്കൗണ്ട്[^\n.!?;।॥]{0,20}(?:അടയ്ക്കും|ബ്ലോക്ക്)|അറസ്റ്റ്)",
        r"(?:এখনই|তৎক্ষণাৎ|অ্যাকাউন্ট[^\n.!?;।॥]{0,20}(?:বন্ধ|ব্লক)|গ্রেপ্তার)",
        r"(?:लगेच|तात्काळ|खाते[^\n.!?;।॥]{0,20}(?:बंद|ब्लॉक)|अटक)",
        r"(?:તાત્કાલિક|હમણાં|ખાતું[^\n.!?;।॥]{0,20}(?:બંધ|બ્લોક)|ધરપકડ)",
        r"(?:ਤੁਰੰਤ|ਹੁਣੇ|ਖਾਤਾ[^\n.!?;।॥]{0,20}(?:ਬੰਦ|ਬਲਾਕ)|ਗ੍ਰਿਫ਼ਤਾਰ)",
        r"(?:ତୁରନ୍ତ|ବର୍ତ୍ତମାନ|ଖାତା[^\n.!?;।॥]{0,20}(?:ବନ୍ଦ|ବ୍ଲକ୍)|ଗିରଫ)",
        r"\b(?:aaj|abhi|turant|khata band|account band ho jayega|band ho jayega|abhi karo)\b",
    ]),
    ("payment", "Payment / UPI instruction", 24, [
        r"(?:\b(?:approve|accept|send|transfer|pay|scan|collect|request|enter|add)\b[^\n.!?;।॥]{0,45}\b(?:upi|payment|money|amount|qr code|collect request|beneficiary|account number)\b|\b(?:upi|payment|money|amount|qr code|collect request)\b[^\n.!?;।॥]{0,45}\b(?:approve|accept|send|transfer|pay|scan|collect|request|enter|add)\b|\b(?:collect request|payment link|send money|scan the code|money transfer)\b)",
        r"(?:पैसे|रुपये|भुगतान|यूपीआई|क्यूआर|स्कैन[^\n.!?;।॥]{0,20}(?:कोड|करें)|ट्रांसफर|भेजें)",
        r"(?:ಹಣ|ಪಾವತಿ|ಯುಪಿಐ|ಕ್ಯೂಆರ್|ಸ್ಕ್ಯಾನ್|ಹಣ\s*ಕಳುಹಿಸಿ)",
        r"(?:பணம்|பணம்\s*அனுப்ப|கட்டணம்|யுபிஐ|க்யூஆர்|ஸ்கேன்)",
        r"(?:డబ్బు|చెల్లింపు|యూపీఐ|క్యూఆర్|స్కాన్|పంపండి)",
        r"(?:പണം|പേയ്മെന്റ്|യുപിഐ|ക്യുആർ|സ്കാൻ|അയയ്ക്കുക)",
        r"(?:টাকা|পেমেন্ট|ইউপিআই|কিউআর|স্ক্যান|পাঠান)",
        r"(?:पैसे|रक्कम|पेमेंट|यूपीआय|क्यूआर|स्कॅन|पाठवा)",
        r"(?:પૈસા|ચુકવણી|યુપીઆઈ|ક્યુઆર|સ્કેન|મોકલો)",
        r"(?:ਪੈਸੇ|ਭੁਗਤਾਨ|ਯੂਪੀਆਈ|ਕਿਊਆਰ|ਸਕੈਨ|ਭੇਜੋ)",
        r"(?:ଟଙ୍କା|ଦେୟ|ୟୁପିଆଇ|କ୍ୟୁଆର|ସ୍କାନ|ପଠାନ୍ତୁ)",
        r"\b(?:paise bhejo|paisa bhejo|payment karo|upi karo|scan karo|transfer karo)\b",
    ]),
    ("remote", "Remote-access or screen-sharing request", 30, [
        r"\b(?:anydesk|teamviewer|quick support|remote access|screen sharing|share your screen|install this app)\b",
        r"(?:ऐप\s*इंस्टॉल|स्क्रीन\s*शेयर|स्क्रीन\s*दिखाइए|रिमोट\s*एक्सेस|ऐप\s*डाउनलोड)",
        r"(?:ಆ್ಯಪ್\s*ಇನ್‌ಸ್ಟಾಲ್|ಸ್ಕ್ರೀನ್\s*ಶೇರ್|ರಿಮೋಟ್\s*ಆಕ್ಸೆಸ್)",
        r"(?:செயலி\s*நிறுவ|திரையைப்\s*பகிர|ரிமோட்\s*அணுகல்)",
        r"(?:యాప్\s*ఇన్‌స్టాల్|స్క్రీన్\s*షేర్|రిమోట్\s*యాక్సెస్)",
        r"(?:ആപ്പ്\s*ഇൻസ്റ്റാൾ|സ്ക്രീൻ\s*ഷെയർ|റിമോട്ട്\s*ആക്സസ്)",
        r"(?:অ্যাপ\s*ইনস্টল|স্ক্রিন\s*শেয়ার|রিমোট\s*অ্যাক্সেস)",
        r"(?:अॅप\s*इन्स्टॉल|स्क्रीन\s*शेअर|रिमोट\s*अॅक्सेस)",
        r"(?:એપ\s*ઇન્સ્ટોલ|સ્ક્રીન\s*શેર|રિમોટ\s*એક્સેસ)",
        r"(?:ਐਪ\s*ਇੰਸਟਾਲ|ਸਕ੍ਰੀਨ\s*ਸ਼ੇਅਰ|ਰਿਮੋਟ\s*ਐਕਸੈਸ)",
        r"(?:ଆପ୍\s*ଇନଷ୍ଟଲ|ସ୍କ୍ରିନ୍\s*ସେୟାର|ରିମୋଟ୍\s*ଆକ୍ସେସ)",
        r"\b(?:anydesk|teamviewer|screen share karo|app install karo|remote app download)\b",
    ]),
    ("link", "Link or app-install request", 16, [
        r"\b(?:click this link|open this link|download this apk|install this application|unknown app|shortened link)\b",
        r"(?:लिंक\s*(?:खोलें|क्लिक|पर\s*क्लिक)|एपीके\s*डाउनलोड|ऐप\s*इंस्टॉल)",
        r"(?:ಲಿಂಕ್\s*(?:ತೆರೆಯಿರಿ|ಕ್ಲಿಕ್)|ಎಪಿಕೆ\s*ಡೌನ್‌ಲೋಡ್)",
        r"(?:இணைப்பை\s*(?:திற|அழுத்த)|லிங்க்\s*கிளிக்|ஏபிகே\s*பதிவிறக்க)",
        r"(?:లింక్\s*(?:ఓపెన్|క్లిక్)|ఏపీకే\s*డౌన్‌లోడ్)",
        r"(?:ലിങ്ക്\s*(?:തുറക്കൂ|ക്ലിക്ക്)|എപികെ\s*ഡൗൺലോഡ്)",
        r"(?:লিংক\s*(?:খুলুন|ক্লিক)|এপিকে\s*ডাউনলোড)",
        r"(?:लिंक\s*(?:उघडा|क्लिक)|एपीके\s*डाउनलोड)",
        r"(?:લિંક\s*(?:ખોલો|ક્લિક)|એપિકે\s*ડાઉનલોડ)",
        r"(?:ਲਿੰਕ\s*(?:ਖੋਲ੍ਹੋ|ਕਲਿੱਕ)|ਏਪੀਕੇ\s*ਡਾਊਨਲੋਡ)",
        r"(?:ଲିଙ୍କ୍\s*(?:ଖୋଲନ୍ତୁ|କ୍ଲିକ୍)|ଏପିକେ\s*ଡାଉନଲୋଡ୍)",
    ]),
    ("secrecy", "Isolation / secrecy pressure", 14, [
        r"\b(?:don't tell anyone|do not tell anyone|keep this confidential|stay on the line|don't disconnect|do not disconnect)\b",
        r"(?:किसी\s*को\s*मत\s*बताइए|किसी\s*को\s*मत\s*बताओ|फोन\s*मत\s*काटिए|कॉल\s*मत\s*काटें)",
        r"(?:ಯಾರಿಗೂ\s*ಹೇಳಬೇಡಿ|ಕರೆ\s*ಕಟ್\s*ಮಾಡಬೇಡಿ)",
        r"(?:யாரிடமும்\s*சொல்லாதீர்கள்|அழைப்பை\s*துண்டிக்காதீர்கள்)",
        r"(?:ఎవరికీ\s*చెప్పకండి|కాల్\s*కట్\s*చేయకండి)",
        r"(?:ആരോടും\s*പറയരുത്|കോൾ\s*കട്ട്\s*ചെയ്യരുത്)",
        r"(?:কাউকে\s*বলবেন\s*না|কল\s*কাটবেন\s*না)",
        r"(?:कोणाला\s*सांगू\s*नका|फोन\s*ठेवू\s*नका)",
        r"(?:કોઈને\s*કહેશો\s*નહીં|કોલ\s*કાપશો\s*નહીં)",
        r"(?:ਕਿਸੇ\s*ਨੂੰ\s*ਨਾ\s*ਦੱਸੋ|ਕਾਲ\s*ਨਾ\s*ਕੱਟੋ)",
        r"(?:କାହାକୁ\s*କୁହନ୍ତୁ\s*ନାହିଁ|କଲ୍\s*କାଟନ୍ତୁ\s*ନାହିଁ)",
    ]),
    ("kyc", "KYC / account-update pretext", 10, [
        r"\b(?:kyc|re-?verification|verify your account|update your details|account verification)\b",
        r"(?:केवाईसी|खाता\s*सत्यापन|विवरण\s*अपडेट|खाता\s*वेरिफाई)",
        r"(?:ಕೆವೈಸಿ|ಖಾತೆ\s*ಪರಿಶೀಲನೆ|ವಿವರ\s*ನವೀಕರಿಸಿ)",
        r"(?:கேஒய்சி|கணக்கு\s*சரிபார்ப்பு|விவரங்களை\s*புதுப்பி)",
        r"(?:కేవైసీ|ఖాతా\s*ధృవీకరణ|వివరాలు\s*అప్‌డేట్)",
        r"(?:കെവൈസി|അക്കൗണ്ട്\s*സ്ഥിരീകരണം|വിവരങ്ങൾ\s*പുതുക്കുക)",
        r"(?:কেওয়াইসি|অ্যাকাউন্ট\s*যাচাই|তথ্য\s*আপডেট)",
        r"(?:केवायसी|खाते\s*पडताळणी|माहिती\s*अपडेट)",
        r"(?:કેવાયસી|ખાતા\s*ચકાસણી|વિગતો\s*અપડેટ)",
        r"(?:ਕੇਵਾਈਸੀ|ਖਾਤਾ\s*ਤਸਦੀਕ|ਵੇਰਵੇ\s*ਅਪਡੇਟ)",
        r"(?:କେୱାଇସି|ଖାତା\s*ଯାଞ୍ଚ|ବିବରଣୀ\s*ଅପଡେଟ୍)",
    ]),
    ("refund", "Refund / prize / unexpected-benefit lure", 12, [
        r"\b(?:cashback|lottery|prize money|you have won|refund is pending|claim your reward)\b",
        r"(?:कैशबैक|लॉटरी|इनाम|आपने\s*जीत|रिफंड\s*लंबित|पुरस्कार)",
        r"(?:ಕ್ಯಾಶ್‌ಬ್ಯಾಕ್|ಲಾಟರಿ|ಬಹುಮಾನ|ನೀವು\s*ಗೆದ್ದಿದ್ದೀರಿ|ಮರುಪಾವತಿ)",
        r"(?:கேஷ்பேக்|லாட்டரி|பரிசு|நீங்கள்\s*வென்றீர்கள்|பணம்\s*திரும்ப)",
        r"(?:క్యాష్‌బ్యాక్|లాటరీ|బహుమతి|మీరు\s*గెలిచారు)",
        r"(?:ക്യാഷ്ബാക്ക്|ലോട്ടറി|സമ്മാനം|നിങ്ങൾ\s*വിജയിച്ചു)",
        r"(?:ক্যাশব্যাক|লটারি|পুরস্কার|আপনি\s*জিতেছেন)",
        r"(?:कॅशबॅक|लॉटरी|बक्षीस|तुम्ही\s*जिंकलात)",
        r"(?:કેશબેક|લોટરી|ઇનામ|તમે\s*જીત્યા|રિફંડ)",
        r"(?:ਕੈਸ਼ਬੈਕ|ਲਾਟਰੀ|ਇਨਾਮ|ਤੁਸੀਂ\s*ਜਿੱਤੇ|ਰਿਫੰਡ)",
        r"(?:କ୍ୟାଶବ୍ୟାକ୍|ଲଟେରୀ|ପୁରସ୍କାର|ଆପଣ\s*ଜିତିଛନ୍ତି|ରିଫଣ୍ଡ)",
    ]),
]


# Roman-script regional speech is common in real STT output. Prisma may render
# the local-language words in Latin characters while retaining English tokens
# such as OTP, bank, account, AnyDesk and UPI. These patterns complement the
# native-script patterns above; they are intentionally phrase-based.
_ROMAN_REGIONAL_PATTERNS = {
    "credential": [
        # Kannada: nimma mobile-ge banda OTP heli / OTP tilisi
        r"\b(?:nimma|nimm|nimma mobile(?:ge|alli)?|mobile(?:ge|alli)?)\b[^\n.!?;।॥]{0,65}\b(?:otp|pin|password)\b[^\n.!?;।॥]{0,35}\b(?:heli|heLi|tilisi|kodi|kodu|hELi)\b",
        r"\b(?:otp|pin|password)\b[^\n.!?;।॥]{0,45}(?:ಹೇಳಿ|ಹೇಳಿ|ತಿಳಿಸಿ|ಕೊಡಿ|ಕಳುಹಿಸಿ)",
        r"\b(?:otp|pin|password)\b[^\n.!?;।॥]{0,45}\b(?:heli|tilisi|kodi|kodu)\b",
        # Malayalam: mobile-il vanna OTP parayoo / OTP parayuka
        r"\b(?:ningalude|ningalude mobile|mobile-il|phone-il)\b[^\n.!?;।॥]{0,65}\b(?:otp|pin|password)\b[^\n.!?;।॥]{0,35}\b(?:parayoo|parayu|parayuka|parayuka|nalku|ayakku)\b",
        r"\b(?:otp|pin|password)\b[^\n.!?;।॥]{0,45}(?:പറയൂ|പറയോ|പറയുക|നൽകൂ|അയയ്ക്കൂ)",
        r"\b(?:otp|pin|password)\b[^\n.!?;।॥]{0,40}\b(?:parayoo|parayu|parayuka|paranju\s*tharu|nalku|ayakku)\b",
        # Gujarati: mobile par aavelo OTP mane kahjo / OTP aapo
        r"\b(?:tamaro|tamari|tamara|mobile par aavelo|phone par aavelo)\b[^\n.!?;।॥]{0,65}\b(?:otp|pin|password)\b[^\n.!?;।॥]{0,35}\b(?:mane kahjo|kahjo|kaho|aapo|moklo|janavo)\b",
        r"\b(?:otp|pin|password)\b[^\n.!?;।॥]{0,45}(?:કહેજો|કહો|આપો|મોકલો)",
        r"\b(?:otp|pin|password)\b[^\n.!?;।॥]{0,40}\b(?:mane\s*kahjo|kahjo|kaho|kahi\s*do|aapo|aapjo|moklo)\b",
        # Broad Romanised Indian-language imperative forms.
        r"\b(?:otp|pin|password|cvv)\b[^\n.!?;।॥]{0,55}\b(?:batao|bataye|batayiye|bolo|boliye|bhejo|bhejiye|dijiye|de\s*do|cheppandi|cheppu|sollunga|solunga|parayoo|parayu|parayuka|heli|helthira|tilisi|kodi|kahjo|kaho|kahi\s*do|aapo|aapjo|moklo)\b",
    ],
    "urgency": [
        r"\b(?:nimma|ninna|ningalude|tamara|tamaro|apnar|tumcha|ungal)\b[^\n.!?;।॥]{0,55}\b(?:account|bank account)\b[^\n.!?;।॥]{0,35}\b(?:block|close|band|suspend|aakum|agutte|aagum|aakum)\b",
        r"\b(?:account|bank account)\b[^\n.!?;।॥]{0,45}\b(?:block|close|band|suspend)\b[^\n.!?;।॥]{0,45}\b(?:aagutte|agutte|aakum|aipothundi|aagum|thai jashe|hoil)\b",
        r"(?:account|bank account)[^\n.!?;।॥]{0,45}(?:block|close|ಬಂಧ|બંધ)[^\n.!?;।॥]{0,45}(?:ಆಗುತ್ತೆ|ಆಗುತ್ತದೆ|ಆಗಲಿದೆ|ആകും|ആകും|થઈ જશે|બંધ થઈ જશે)",
        r"\b(?:illandre|illenkil|illaina|nahi to|nahitar|nahi tar|nahi to)\b[^\n.!?;।॥]{0,55}\b(?:account|bank account)\b[^\n.!?;।॥]{0,30}\b(?:close|block|band)\b",
        r"\b(?:ivattu|ee roju|innu|inniku|aaje|aaj|abhi|turant)\b[^\n.!?;।॥]{0,35}\b(?:account|bank account)\b[^\n.!?;।॥]{0,25}\b(?:block|close|band)\b",
    ],
    "authority": [
        r"\b(?:bank ninda|bank inda|bank nunchi|bank se|bank ki taraf se|bankil ninn|bank theke|bank kadun|bank mathi|bank tarafthi)\b",
        r"\b(?:bank customer care|bank support|customer care nunchi|customer support nunchi)\b",
    ],
    "payment": [
        r"\b(?:paisa transfer|paise bhejo|payment approve|request approve|approve cheyyandi|approve karo|scan karo|scan cheyyandi|money transfer)\b",
        r"\b(?:panam ayakku|paisa moklo|paisa aapo|paisa transfer karo|dabbulu pampandi|hana kaluhisi|hana kodi)\b",
    ],
    "remote": [
        r"\b(?:anydesk|teamviewer|quick support)\b[^\n.!?;।॥]{0,60}\b(?:install|download|cheyyandi|maadi|madi|karo|chesthe|chestanu|access code|code cheppu|code heli|code parayu)\b",
        r"\b(?:screen sharing|screen share|remote access)\b[^\n.!?;।॥]{0,45}\b(?:on|enable|maadi|cheyyandi|karo|pannu|aakku)\b",
        r"\b(?:app install chesi|app download chesi)\b[^\n.!?;।॥]{0,50}\b(?:code|access|screen|share)\b",
    ],
    "link": [
        r"\b(?:link open cheyyandi|link click cheyyandi|apk install cheyyandi|app install chesi)\b",
    ],
    "secrecy": [
        r"\b(?:yarigu helbedi|yarigu helabedi|yaarigu helbedi|aarodum parayaruthu|aarodum parayalle|kisi ko mat batana|kisi ko mat bataye|koi ne kehsho nahi)\b",
    ],
    "kyc": [
        r"\b(?:kyc update cheyyandi|kyc update karo|kyc update cheyyanam|kyc complete cheyyandi|kyc pending hai)\b",
    ],
    "refund": [
        r"\b(?:refund pending|refund process start|prize won|lottery gelicharu)\b",
    ],
}
for _key, _title, _points, _patterns in PATTERNS:
    _patterns.extend(_ROMAN_REGIONAL_PATTERNS.get(_key, []))

COMBOS = [
    ({"authority", "credential"}, 14, "Authority claim combined with credential request"),
    ({"urgency", "payment"}, 10, "Urgency combined with payment instruction"),
    ({"remote", "payment"}, 14, "Remote access combined with payment activity"),
    ({"secrecy", "credential"}, 10, "Secrecy combined with credential request"),
    ({"refund", "payment"}, 8, "Unexpected benefit combined with payment instruction"),
    ({"authority", "urgency", "credential"}, 12, "Impersonation, urgency and credential theft sequence"),
]

def _normalise(text):
    text = unicodedata.normalize("NFKC", text).lower()
    return re.sub(r"\s+", " ", text).strip()

def _is_safety_or_negated_context(text, start, end, key):
    """Avoid scoring protective advice and explicit negation as attacker requests."""
    # Limit negation/safety checks to the sentence containing this match. This
    # prevents an earlier warning from suppressing a later, separate scam request.
    boundaries = ".!?;\n।॥"
    sentence_start = max((text.rfind(ch, 0, start) for ch in boundaries), default=-1) + 1
    end_positions = [text.find(ch, end) for ch in boundaries if text.find(ch, end) != -1]
    sentence_end = min(end_positions) if end_positions else len(text)
    sentence = text[sentence_start:sentence_end]
    local_start = start - sentence_start
    left = sentence[:local_start]
    right = sentence[(end - sentence_start):]
    around = sentence
    safety_phrases = [
        r"\b(?:never|don't|do not|dont|must not|should not|cannot|can't|avoid)\b[^\n.!?;।॥]{0,65}\b(?:share|tell|give|send|disclose|reveal|provide|install|pay|transfer|approve)\b",
        r"\b(?:bank employees|bank staff|we|our staff)\b[^\n.!?;।॥]{0,45}\b(?:will not|won't|never|do not|don't)\b",
        r"\b(?:do not|don't|never)\b[^\n.!?;।॥]{0,50}\b(?:ask for|request)\b[^\n.!?;।॥]{0,35}\b(?:otp|pin|password|cvv)\b",
        r"\b(?:official|genuine|secure)\s+(?:bank|banking)\s+app\b",
        r"(?:ఎవరికీ\s*చెప్పకండి|చెప్పకండి|అడగకూడదు|షేర్\s*చేయకండి|పంచుకోకండి)",
        r"(?:किसी\s*को\s*मत\s*बताइए|मत\s*बताओ|नहीं\s*बताएं|नहीं\s*मांगते)",
        r"(?:ಯಾರಿಗೂ\s*ಹೇಳಬೇಡಿ|ಹೇಳಬೇಡಿ|ಕೇಳುವುದಿಲ್ಲ)",
        r"(?:யாரிடமும்\s*சொல்லாதீர்கள்|சொல்லாதீர்கள்|கேட்கமாட்டார்கள்)",
        r"\b(?:otp|pin|password)\b[^\n.!?;।॥]{0,45}\b(?:yarigu helbedi|yarigu helabedi|helbedi|parayaruthu|parayalle|mat batana|mat bataye|kehsho nahi)\b",
        r"\b(?:bank employees|bank staff)\b[^\n.!?;।॥]{0,45}\b(?:otp adagakoodadu|otp adagaru|otp chodikkaruthu|otp nahi maangte)\b",
        r"\b(?:never|don't|do not|dont|should not|must not)\b[^\n.!?;।॥]{0,55}\b(?:share|tell|give|send|disclose|reveal|provide)\b[^\n.!?;।॥]{0,35}\b(?:otp|pin|password|cvv)\b",
    ]
    if any(re.search(p, around, re.I) for p in safety_phrases):
        # A protective warning should not be treated as a request for the sensitive action.
        if key in {"credential", "remote", "payment", "link", "secrecy"}:
            return True
    # Common explicit negation immediately before an action request.
    if key == "credential" and re.search(
        r"(?:never|don't|do not|dont|should not|must not|avoid|not)\s+(?:ever\s+)?(?:share|tell|give|send|disclose|reveal|provide|ask for)[^\n.!?;।॥]{0,55}$",
        left, re.I,
    ):
        return True
    # 'I went to the bank today' is not urgency; only threats/pressure count.
    if key == "urgency" and re.search(r"\b(?:today|aaj|this morning|this evening)\b", around, re.I) and not re.search(
        r"\b(?:or else|otherwise|immediately|urgent|final warning|last chance|will be blocked|will be suspended|arrest|legal action)\b",
        around, re.I,
    ):
        return True
    return False


def analyze_transcript(transcript):
    if not transcript or not transcript.strip():
        raise ValueError("Transcript is empty.")
    text = _normalise(transcript)
    found, signals = set(), []
    score = 0
    for key, title, points, patterns in PATTERNS:
        accepted = None
        for pattern in patterns:
            for match in re.finditer(pattern, text, re.I):
                if not _is_safety_or_negated_context(text, match.start(), match.end(), key):
                    accepted = match
                    break
            if accepted:
                break
        if accepted:
            found.add(key)
            # Generic bank/authority mentions are context only, not a scam signal by themselves.
            if key == "authority" and not (found & {"credential", "urgency", "payment", "remote", "link", "secrecy", "kyc", "refund"}):
                continue
            score += points
            evidence = text[max(0, accepted.start()-55):min(len(text), accepted.end()+65)]
            signals.append({
                "key": key, "title": title, "points": points,
                "evidence": "…" + evidence + "…"
            })
    # Contextualise weak signals: a generic institution mention is not suspicious alone.
    actionable = {"credential", "remote", "link", "secrecy", "kyc", "refund"}
    if "payment" in found and not (found & (actionable | {"urgency"})):
        signals = [x for x in signals if x["key"] != "payment"]
        found.discard("payment")
        score = sum(x["points"] for x in signals)
    if "authority" in found and not (found & (actionable | {"payment", "urgency"})):
        signals = [x for x in signals if x["key"] != "authority"]
        found.discard("authority")
        score = sum(x["points"] for x in signals)
    # Apply the strongest applicable sequence bonus only once.
    applicable = [
        (len(required), bonus, title)
        for required, bonus, title in COMBOS if required.issubset(found)
    ]
    if applicable:
        _, bonus, title = max(applicable)
        score += bonus
        signals.append({
            "key": "sequence", "title": title, "points": bonus,
            "evidence": "Multiple indicators co-occur in this transcript."
        })
    score = min(100, score)
    if score >= 75:
        level = "CRITICAL"
        advice = "End the interaction. Do not share authentication codes, credentials, payment details or screen access. Verify through an independently sourced official channel."
        warning = "High risk warning. Do not share OTPs, PINs or passwords. Do not send money or share your screen. Verify independently."
    elif score >= 50:
        level = "HIGH"
        advice = "Pause. Do not follow payment or credential instructions. Contact the organisation using its official app or published number."
        warning = "Caution. This conversation contains suspicious requests. Do not share sensitive information or make a payment."
    elif score >= 25:
        level = "MEDIUM"
        advice = "Verify the caller independently. Never disclose authentication codes during an unexpected call."
        warning = "Please pause and independently verify this caller before taking action."
    else:
        level = "LOW"
        advice = "No configured high-risk pattern was detected in this transcript. This does not prove that the caller is genuine or that the interaction is safe."
        warning = "Reminder. Never share OTPs, PINs or passwords over a call."
    return {
        "score": score, "level": level, "signals": signals,
        "signal_count": len(signals), "advice": advice, "warning": warning
    }
