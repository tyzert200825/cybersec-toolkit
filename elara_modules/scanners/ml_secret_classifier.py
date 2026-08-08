#!/usr/bin/env python3
"""
ML Secret Classifier
====================
AI-fallback layer for the GH Archive Secret Hunter pipeline.

Implements the approach from Yunus Aydın's article:
- Phase 1: LLM-based classification (here: TF-IDF + Logistic Regression as a fast local substitute)
- Phase 2: Extract patterns from labeled data to build regex grammar
- Phase 3: Regex-first, ML-fallback — only use ML for ambiguous messages

Training labels come from the regex tiers:
  tier0/tier1  → positive (suspicious)
  clean        → negative (not suspicious)
  tier2        → ambiguous (used for ML training, not for regex labels)

Usage:
    # Train from a GH Archive hour file
    python3 ml_secret_classifier.py --train --hour 2024-01-15-12

    # Classify a single message
    python3 ml_secret_classifier.py --predict "remove leaked api key from config"

    # Evaluate on held-out data
    python3 ml_secret_classifier.py --evaluate --hour 2024-01-15-14
"""

import argparse
import json
import os
import pickle
import re
import sys
import time
from pathlib import Path

# ─── Regex tiers (imported from main script) ─────────────────────────────────

HIGH_CONFIDENCE_ACTION_VERBS = [
    "remove", "delete", "revoke", "invalidate", "rotate", "regenerate",
    "leak", "leaked", "expose", "exposed", "compromise", "compromised", "fix", "fixed",
]

HIGH_CONFIDENCE_OBJECT_NOUNS = [
    "api_key", "apikey", "api-key", "access_token", "auth_token",
    "private_key", "secret_key", "client_secret", "credential", "credentials",
    "password", "passwd", "aws_secret", "aws_access_key", "access_key",
    ".env", "dotenv", "token", "secret", "secrets",
    "ssh_key", "signing_key", "encryption_key",
    "service_account", "service_account_key",
    "firebase_key", "gcp_key", "azure_key",
]

BROAD_ACTION_VERBS = [
    "update", "change", "fix", "patch", "clean", "remove", "delete",
    "purge", "wipe", "scrub", "revert", "replace", "move", "rotate",
    "regenerate", "refactor", "strip", "sanitize", "redact", "obfuscate",
]

BROAD_OBJECT_NOUNS = [
    "key", "token", "secret", "password", "credential", "config", "configuration",
    "env", "environment", "auth", "oauth", "jwt",
    "aws", "gcp", "azure", "firebase", "cloudflare", "digitalocean", "linode",
    "vultr", "hetzner", "oracle", "aliyun",
    "stripe", "twilio", "mailgun", "sendgrid", "slack", "slackbot", "discord",
    "github", "gitlab", "bitbucket", "npm", "pypi", "docker", "hubspot",
    "datadog", "newrelic", "sentry", "pagerduty", "grafana", "prometheus",
    "algolia", "elastic", "mongodb", "redis", "postgres", "mysql",
    "supabase", "planetscale", "neon", "railway", "render", "vercel",
    "netlify", "heroku", "fly", "scaleway",
    "openai", "anthropic", "huggingface", "wandb", "weights_and_biases",
    "replicate", "together", "groq", "mistral", "cohere", "perplexity",
    "circleci", "travisci", "jenkins", "buildkite", "github_actions",
    "gitlab_ci", "drone", "argo", "tekton",
    "paypal", "square", "plaid", "coinbase", "binance",
    "vonage", "messagebird", "pusher", "ably",
    "sumologic", "splunk", "logz", "loggly", "papertrail",
    "vault", "sops", "gpg", "age", "kms", "hsm",
    "airtable", "notion", "figma", "asana", "monday", "linear",
    "segment", "amplitude", "mixpanel", "posthog",
    "contentful", "sanity", "strapi", "shopify",
    "zoom", "webex", "intercom", "zendesk", "freshdesk",
]

SECRET_REMOVAL_PATTERNS = [
    re.compile(
        r'\b(remove|delete|revoke|invalidate|rotate|regenerate)\b.*\b(key|token|secret|password|credential)\b',
        re.IGNORECASE
    ),
    re.compile(
        r'\b(fix|patch)\b.*\b(leak|expose|compromise)\b',
        re.IGNORECASE
    ),
    re.compile(
        r'\b(revert)\b.*for.*security.*reason',
        re.IGNORECASE
    ),
]

_HC_VERBS = set(HIGH_CONFIDENCE_ACTION_VERBS)
_HC_NOUNS = set(HIGH_CONFIDENCE_OBJECT_NOUNS)
_BC_VERBS = set(BROAD_ACTION_VERBS)
_BC_NOUNS = set(BROAD_OBJECT_NOUNS)


def normalize(msg: str) -> str:
    return re.sub(r'[^a-z0-9._\- ]', ' ', msg.lower()).replace('-', '_').replace('  ', ' ')


def has_word(text: str, word: str) -> bool:
    pattern = r'(?<![a-z0-9_])' + re.escape(word) + r'(?![a-z0-9_])'
    return bool(re.search(pattern, text))


def any_word(text: str, word_set: set) -> bool:
    for w in word_set:
        if has_word(text, w):
            return True
    return False


def classify_regex(msg: str) -> tuple[str, str]:
    """Return (label, reason) using regex tiers. label is 'suspicious', 'clean', or 'ambiguous'."""
    if not msg or not msg.strip():
        return "clean", "empty"
    
    normalized = normalize(msg)
    
    for pattern in SECRET_REMOVAL_PATTERNS:
        if pattern.search(msg):
            return "suspicious", "tier0"
    
    if any_word(normalized, _HC_VERBS) and any_word(normalized, _HC_NOUNS):
        return "suspicious", "tier1"
    
    if any_word(normalized, _BC_VERBS) and any_word(normalized, _BC_NOUNS):
        return "ambiguous", "tier2"  # ambiguous → ML decides
    
    return "clean", "clean"


# ─── ML Classifier (TF-IDF + Logistic Regression) ────────────────────────────

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "secret_classifier.pkl")


class SecretClassifier:
    """
    Lightweight ML classifier for commit messages.
    Uses TF-IDF features (char + word n-grams) + Logistic Regression.
    Trained on regex-labeled data from GH Archive.
    """
    
    def __init__(self):
        self.pipeline = None
        self.training_stats = {}
    
    def train(self, messages: list[str], labels: list[str], verbose: bool = True):
        """Train the classifier on labeled messages."""
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        
        # Combine word + char n-grams for better pattern capture
        self.pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 3),
                sublinear_tf=True,
                min_df=2,
                max_df=0.95,
                stop_words='english',
                token_pattern=r'(?u)\b[a-z][a-z0-9_]{1,}\b',
            )),
            ('clf', LogisticRegression(
                C=1.0,
                class_weight='balanced',
                max_iter=1000,
                solver='liblinear',
                random_state=42,
            )),
        ])
        
        self.pipeline.fit(messages, labels)
        
        # Store training stats
        from collections import Counter
        label_counts = Counter(labels)
        self.training_stats = {
            "total_samples": len(labels),
            "label_distribution": dict(label_counts),
            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        }
        
        if verbose:
            print(f"  [ml] Trained on {len(labels)} samples")
            for label, count in label_counts.most_common():
                print(f"       {label}: {count}")
    
    def predict(self, message: str) -> tuple[str, float]:
        """Classify a single message. Returns (label, confidence)."""
        if self.pipeline is None:
            return "unknown", 0.0
        
        pred = self.pipeline.predict([message])
        proba = self.pipeline.predict_proba([message])
        
        label = pred[0]
        confidence = max(proba[0])
        
        return label, confidence
    
    def predict_batch(self, messages: list[str]) -> list[tuple[str, float]]:
        """Classify multiple messages. Returns list of (label, confidence)."""
        if self.pipeline is None:
            return [("unknown", 0.0)] * len(messages)
        
        preds = self.pipeline.predict(messages)
        probas = self.pipeline.predict_proba(messages)
        
        results = []
        for i in range(len(messages)):
            results.append((preds[i], max(probas[i])))
        
        return results
    
    def save(self, path: str = MODEL_PATH):
        """Save the trained model to disk."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            pickle.dump({
                'pipeline': self.pipeline,
                'training_stats': self.training_stats,
            }, f)
        print(f"  [ml] Model saved to {path}")
    
    def load(self, path: str = MODEL_PATH) -> bool:
        """Load a trained model from disk. Returns True if loaded."""
        if not os.path.exists(path):
            return False
        with open(path, 'rb') as f:
            data = pickle.load(f)
            self.pipeline = data['pipeline']
            self.training_stats = data['training_stats']
        return True


# ─── Training data generation ────────────────────────────────────────────────

def generate_training_data_from_archive(archive_path: str, max_samples: int = 50000) -> tuple[list[str], list[str]]:
    """
    Generate training data from a GH Archive file using regex tiers as labels.
    
    tier0/tier1 → 'suspicious'
    clean       → 'clean'  
    tier2       → 'ambiguous' (excluded from training — these are what ML should decide on)
    
    Returns (messages, labels) with balanced classes.
    """
    suspicious = []
    clean = []
    ambiguous = []
    
    with open(archive_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            if event.get("type") not in ("PushEvent", "PullRequestEvent"):
                continue
            
            # Extract commit messages
            messages = []
            if event.get("type") == "PushEvent":
                payload = event.get("payload", {})
                if "commits" in payload and payload["commits"]:
                    for commit in payload["commits"]:
                        msg = commit.get("message", "")
                        if msg:
                            messages.append(msg)
            else:
                pr = event.get("payload", {}).get("pull_request", {})
                title = pr.get("title", "")
                if title:
                    messages.append(title)
            
            for msg in messages:
                label, reason = classify_regex(msg)
                if label == "suspicious":
                    suspicious.append(msg)
                elif label == "ambiguous":
                    ambiguous.append(msg)
                else:
                    clean.append(msg)
                
                if len(suspicious) + len(clean) + len(ambiguous) >= max_samples:
                    break
            
            if len(suspicious) + len(clean) + len(ambiguous) >= max_samples:
                break
    
    # Balance the dataset — use all suspicious, equal number of clean + ambiguous
    import random
    random.seed(42)
    
    # Use suspicious + ambiguous as positive (the ML should learn from ambiguous too)
    # Actually: train on suspicious vs clean, then use ML to classify ambiguous at predict time
    max_per_class = min(len(suspicious), len(clean), 10000)
    
    random.shuffle(suspicious)
    random.shuffle(clean)
    random.shuffle(ambiguous)
    
    suspicious_sample = suspicious[:max_per_class]
    clean_sample = clean[:max_per_class]
    
    # Add some ambiguous as "suspicious" (since they have broad verb+noun, they're more likely to be real)
    ambiguous_as_suspicious = ambiguous[:max_per_class // 3]
    
    messages = [m.split('\n')[0] for m in suspicious_sample + ambiguous_as_suspicious + clean_sample]
    labels = (
        ["suspicious"] * len(suspicious_sample) +
        ["suspicious"] * len(ambiguous_as_suspicious) +
        ["clean"] * len(clean_sample)
    )
    
    print(f"  [data] Raw counts — suspicious: {len(suspicious)}, ambiguous: {len(ambiguous)}, clean: {len(clean)}")
    print(f"  [data] Training set — suspicious: {len(suspicious_sample) + len(ambiguous_as_suspicious)}, clean: {len(clean_sample)}")
    
    return messages, labels


# ─── Integrated classifier (regex-first, ML-fallback) ────────────────────────

class IntegratedClassifier:
    """
    Combines regex tiers + ML fallback.
    
    Pipeline:
    1. tier0/tier1 regex → 'suspicious' (high confidence, no ML needed)
    2. 'clean' regex → 'clean' (no keywords at all, no ML needed)
    3. tier2 (ambiguous) → ML decides
    
    This mirrors the article's Phase 3: regex-first, AI-fallback.
    """
    
    def __init__(self, ml_classifier: SecretClassifier = None, ml_threshold: float = 0.65):
        self.ml = ml_classifier
        self.ml_threshold = ml_threshold
        self.stats = {"regex_hits": 0, "ml_hits": 0, "clean": 0}
    
    def classify(self, msg: str) -> tuple[bool, str, float]:
        """
        Classify a commit message.
        Returns (is_suspicious, reason, confidence).
        """
        if not msg or not msg.strip():
            self.stats["clean"] += 1
            return False, "empty", 1.0
        
        # Regex-first
        label, reason = classify_regex(msg)
        
        if label == "suspicious":
            self.stats["regex_hits"] += 1
            return True, f"regex_{reason}", 1.0
        
        if label == "clean":
            self.stats["clean"] += 1
            return False, "regex_clean", 1.0
        
        # ML fallback for ambiguous (tier2) messages
        if self.ml and self.ml.pipeline is not None:
            ml_label, confidence = self.ml.predict(msg.split('\n')[0])
            if ml_label == "suspicious" and confidence >= self.ml_threshold:
                self.stats["ml_hits"] += 1
                return True, f"ml_fallback_{reason}", confidence
        
        self.stats["clean"] += 1
        return False, f"ml_clean_{reason}", 0.5 if self.ml else 0.0
    
    def classify_batch(self, messages: list[str]) -> list[tuple[bool, str, float]]:
        """Classify a batch of messages efficiently."""
        results = []
        ml_messages = []
        ml_indices = []
        
        # First pass: regex
        for i, msg in enumerate(messages):
            if not msg or not msg.strip():
                results.append((False, "empty", 1.0))
                self.stats["clean"] += 1
                continue
            
            label, reason = classify_regex(msg)
            
            if label == "suspicious":
                results.append((True, f"regex_{reason}", 1.0))
                self.stats["regex_hits"] += 1
            elif label == "clean":
                results.append((False, "regex_clean", 1.0))
                self.stats["clean"] += 1
            else:
                # Ambiguous — queue for ML
                results.append(None)
                ml_messages.append(msg.split('\n')[0])
                ml_indices.append(i)
        
        # Second pass: ML for ambiguous
        if ml_messages and self.ml and self.ml.pipeline is not None:
            ml_results = self.ml.predict_batch(ml_messages)
            for idx, (ml_label, confidence) in zip(ml_indices, ml_results):
                if ml_label == "suspicious" and confidence >= self.ml_threshold:
                    results[idx] = (True, f"ml_fallback", confidence)
                    self.stats["ml_hits"] += 1
                else:
                    results[idx] = (False, "ml_clean", confidence)
                    self.stats["clean"] += 1
        else:
            for idx in ml_indices:
                results[idx] = (False, "ambiguous_no_ml", 0.0)
                self.stats["clean"] += 1
        
        return results


# ─── CLI ────────────────────────────────────────────────────────────────────

def cmd_train(args):
    """Train the classifier from GH Archive data."""
    # Import download function from main script
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from gh_secret_hunter import download_archive
    
    archive_path = download_archive(args.hour)
    if not archive_path:
        print(f"[error] Could not download {args.hour}")
        return
    
    print(f"\n[*] Generating training data from {args.hour}...")
    messages, labels = generate_training_data_from_archive(archive_path, max_samples=args.max_samples)
    
    print(f"\n[*] Training ML classifier...")
    classifier = SecretClassifier()
    classifier.train(messages, labels)
    classifier.save(args.model_path)
    
    # Quick self-evaluation
    print(f"\n[*] Self-evaluation on training data...")
    from sklearn.model_selection import cross_val_score
    import numpy as np
    scores = cross_val_score(classifier.pipeline, messages, labels, cv=5, scoring='f1_macro')
    print(f"  5-fold CV F1-macro: {scores.mean():.3f} ± {scores.std():.3f}")
    print(f"  Individual folds: {[f'{s:.3f}' for s in scores]}")


def cmd_predict(args):
    """Classify a single message."""
    classifier = SecretClassifier()
    if not classifier.load(args.model_path):
        print("[error] No trained model found. Run --train first.")
        return
    
    label, confidence = classifier.predict(args.predict)
    print(f"Message: {args.predict}")
    print(f"Label: {label}")
    print(f"Confidence: {confidence:.3f}")


def cmd_evaluate(args):
    """Evaluate the integrated classifier on held-out GH Archive data."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from gh_secret_hunter import download_archive
    
    archive_path = download_archive(args.hour)
    if not archive_path:
        print(f"[error] Could not download {args.hour}")
        return
    
    # Load ML model
    ml = SecretClassifier()
    has_model = ml.load(args.model_path)
    if has_model:
        print(f"[*] Loaded ML model (trained: {ml.training_stats.get('trained_at', '?')})")
    else:
        print(f"[*] No ML model — regex-only mode")
    
    integrated = IntegratedClassifier(ml_classifier=ml if has_model else None)
    
    print(f"\n[*] Evaluating on {args.hour}...")
    
    true_pos = 0  # regex says suspicious, actually suspicious
    true_neg = 0  # regex says clean, actually clean
    ml_suspicious = 0
    ml_clean = 0
    total = 0
    
    with open(archive_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            if event.get("type") != "PushEvent":
                continue
            
            payload = event.get("payload", {})
            if "commits" not in payload or not payload["commits"]:
                continue
            
            for commit in payload.get("commits", []):
                msg = commit.get("message", "")
                if not msg:
                    continue
                
                is_suspicious, reason, confidence = integrated.classify(msg)
                total += 1
                
                if "regex_tier0" in reason or "regex_tier1" in reason:
                    true_pos += 1
                elif "regex_clean" in reason:
                    true_neg += 1
                elif "ml_fallback" in reason:
                    ml_suspicious += 1
                elif "ml_clean" in reason:
                    ml_clean += 1
                
                if total % 10000 == 0:
                    print(f"  [progress] {total} processed — regex_susp: {true_pos}, regex_clean: {true_neg}, ml_susp: {ml_suspicious}, ml_clean: {ml_clean}")
    
    print(f"\n[*] EVALUATION RESULTS ({total} messages)")
    print(f"  Regex suspicious (tier0/tier1): {true_pos}")
    print(f"  Regex clean:                     {true_neg}")
    print(f"  ML flagged suspicious:            {ml_suspicious}")
    print(f"  ML flagged clean:                 {ml_clean}")
    print(f"  Stats: {json.dumps(integrated.stats, indent=2)}")


def main():
    parser = argparse.ArgumentParser(description="ML Secret Classifier — AI-fallback for GH Archive Secret Hunter")
    
    parser.add_argument("--train", action="store_true", help="Train the classifier")
    parser.add_argument("--evaluate", action="store_true", help="Evaluate on held-out data")
    parser.add_argument("--predict", type=str, help="Classify a single message")
    parser.add_argument("--hour", type=str, default="2024-01-15-12", help="GH Archive hour key")
    parser.add_argument("--max-samples", type=int, default=50000, help="Max training samples")
    parser.add_argument("--model-path", type=str, default=MODEL_PATH, help="Model file path")
    
    args = parser.parse_args()
    
    if args.train:
        cmd_train(args)
    elif args.predict:
        cmd_predict(args)
    elif args.evaluate:
        cmd_evaluate(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
