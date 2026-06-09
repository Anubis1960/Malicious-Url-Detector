import joblib
import numpy as np
import pandas as pd

from src.infra.model.prepare import extract_url_features

models = {
    'Random Forest': joblib.load('src/infra/model/Random Forest.pkl'),
    'Gradient Boosting': joblib.load('src/infra/model/Gradient Boosting.pkl'),
    'Ada Boost': joblib.load('src/infra/model/Ada Boost.pkl')
}

LABEL_MAP = {
    0: 'benign',
    1: 'defacement',
    2: 'phishing',
    3: 'malware',
}


def predict_url(url):
    """
    Predict if a URL is malicious using ensemble of models.

    Parameters:
    url (str): The URL to analyze

    Returns:
    dict: Dictionary containing predictions and confidence scores
    """

    # Extract features from URL
    features_dict = extract_url_features(url)
    feature_names = [
        'url_len', 'digits', 'letters', 'domain_ngram_entropy',
        'path_depth', 'path_entropy', 'consonant_ratio', 'vowel_ratio',
        'digit_ratio', 'avg_token_length', 'token_count'
    ]

    features_df = pd.DataFrame([features_dict])[feature_names]

    # Make predictions with each model
    predictions = {}
    probabilities = {}

    for name, model in models.items():
        pred = model.predict(features_df)[0]
        proba = model.predict_proba(features_df)[0]

        predictions[name] = LABEL_MAP[pred]
        probabilities[name] = {
            'benign': proba[0],
            'defacement': proba[1],
            'phishing': proba[2],
            'malware': proba[3],
        }

    # Ensemble prediction using majority voting on actual labels
    all_predictions = [predictions[m] for m in models.keys()]

    # Find the most common prediction
    from collections import Counter
    ensemble_prediction = Counter(all_predictions).most_common(1)[0][0]

    # Calculate average confidence for each class across models
    avg_benign_prob = np.mean([probabilities[m]['benign'] for m in models.keys()])
    avg_defacement_prob = np.mean([probabilities[m]['defacement'] for m in models.keys()])
    avg_phishing_prob = np.mean([probabilities[m]['phishing'] for m in models.keys()])
    avg_malware_prob = np.mean([probabilities[m]['malware'] for m in models.keys()])

    # Get confidence for the ensemble prediction
    ensemble_confidence = {
        'benign': avg_benign_prob,
        'defacement': avg_defacement_prob,
        'phishing': avg_phishing_prob,
        'malware': avg_malware_prob
    }

    # Get confidence score for the predicted class
    confidence_score = ensemble_confidence[ensemble_prediction]

    # Return comprehensive results
    return {
        'url': url,
        'ensemble_prediction': ensemble_prediction,
        'ensemble_confidence': confidence_score,
        'ensemble_confidence_all_classes': ensemble_confidence,
        'individual_predictions': predictions,
        'individual_probabilities': probabilities,
        'features_extracted': features_dict
    }