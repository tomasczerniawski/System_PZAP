import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from imblearn.over_sampling import SMOTE
import pickle


def train_spam_classifier_and_classify_emails():
    df = pd.read_csv("emails.csv")

    X = df["text"].tolist()
    y = df["spam"].tolist()

    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    X_features = vectorizer.fit_transform(X)

    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X_features, y)

    logistic_regression = LogisticRegression(max_iter=1000, class_weight="balanced")
    random_forest = RandomForestClassifier(
        n_estimators=200, class_weight="balanced_subsample"
    )

    voting_classifier = VotingClassifier(
        estimators=[("lr", logistic_regression), ("rf", random_forest)], voting="soft"
    )

    voting_classifier.fit(X_resampled, y_resampled)

    with open("voting_classifier.pkl", "wb") as file:
        pickle.dump(voting_classifier, file)
    with open("vectorizer.pkl", "wb") as file:
        pickle.dump(vectorizer, file)

    return voting_classifier, vectorizer


def classify_email(message_body, voting_classifier, vectorizer):
    processed_message = vectorizer.transform([message_body])

    prediction = voting_classifier.predict(processed_message)

    predicted_category = "spam" if prediction == 1 else "not spam"

    return predicted_category
