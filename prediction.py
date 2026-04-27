import pickle
import joblib
import numpy as np
import pandas as pd


ALL_42_FEATURES = [
    'dur', 'proto', 'service', 'state',
    'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload',
    'sloss', 'dloss', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'swin', 'stcpb', 'dtcpb',
    'dwin', 'tcprtt', 'synack', 'ackdat',
    'smean', 'dmean', 'trans_depth',
    'response_body_len', 'ct_srv_src',
    'ct_state_ttl', 'ct_dst_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm',
    'ct_dst_src_ltm', 'is_ftp_login',
    'ct_ftp_cmd', 'ct_flw_http_mthd',
    'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
]

TO_FILL_ZERO = [
    'rate', 'dinpkt', 'sjit', 'djit',
    'stcpb', 'dtcpb', 'ackdat',
    'ct_dst_ltm', 'ct_ftp_cmd', 'ct_src_ltm'
]

CAT_COLS_FALLBACK = {
    'proto':   'tcp',
    'service': '-',
    'state':   'CON',
}

ENSEMBLE_WEIGHT = 0.5
IF_WEIGHT       = 0.5
ATTACK_RATIO_THRESHOLD = 0.3


def load_artifacts(models_dir: str) -> dict:
    import os
    p = models_dir

    with open(os.path.join(p, 'encoders',      'nidss_encoders.pkl'),   'rb') as f:
        encoders = pickle.load(f)
    with open(os.path.join(p, 'scalers',       'nidss_scaler.pkl'),     'rb') as f:
        scaler = pickle.load(f)
    with open(os.path.join(p, 'feature_order', 'nidss_features.pkl'),   'rb') as f:
        nids_features = pickle.load(f)
    with open(os.path.join(p, 'anomaly',       'isolation_forest.pkl'), 'rb') as f:
        iso_forest = pickle.load(f)
    with open(os.path.join(p, 'scalers',       'if_scaler.pkl'),        'rb') as f:
        if_scaler = pickle.load(f)
    with open(os.path.join(p, 'feature_order', 'if_feature_order.pkl'), 'rb') as f:
        if_feature_order = pickle.load(f)

    model_xgb  = joblib.load(os.path.join(p, 'classifiers', 'final_xgb.pkl'))
    model_lgbm = joblib.load(os.path.join(p, 'classifiers', 'final_lgbm.pkl'))
    model_rf   = joblib.load(os.path.join(p, 'classifiers', 'final_rf.pkl'))
    threshold  = joblib.load(os.path.join(p, 'threshold',   'final_threshold.pkl'))

    return {
        'encoders':        encoders,
        'scaler':          scaler,
        'nids_features':   nids_features,
        'iso_forest':      iso_forest,
        'if_scaler':       if_scaler,
        'if_feature_order': if_feature_order,
        'model_xgb':       model_xgb,
        'model_lgbm':      model_lgbm,
        'model_rf':        model_rf,
        'threshold':       threshold,
    }


def preprocess(raw_df: pd.DataFrame, artifacts: dict) -> pd.DataFrame:
    encoders      = artifacts['encoders']
    scaler        = artifacts['scaler']
    nids_features = artifacts['nids_features']

    extracted_df = raw_df.copy()

    for col, fallback in CAT_COLS_FALLBACK.items():
        known_values = encoders[col].classes_
        extracted_df[col] = extracted_df[col].apply(
            lambda x: x if x in known_values else fallback
        )
        extracted_df[col] = encoders[col].transform(extracted_df[col])

    for feature in TO_FILL_ZERO:
        extracted_df[feature] = 0

    extracted_df = extracted_df[ALL_42_FEATURES]
    extracted_df = extracted_df.replace([np.inf, -np.inf], 0)
    extracted_df = extracted_df.fillna(0)

    X_scaled = scaler.transform(extracted_df)
    X_df     = pd.DataFrame(X_scaled, columns=ALL_42_FEATURES)

    X_df.drop(columns=TO_FILL_ZERO, inplace=True)

    X_df = X_df[nids_features]

    return X_df

def run_isolation_forest(X_df: pd.DataFrame, artifacts: dict) -> tuple:
    """
    Run Isolation Forest, flip and normalize scores to attack probability.
    Returns (if_attack_prob, if_predictions)
    """
    iso_forest       = artifacts['iso_forest']
    if_scaler        = artifacts['if_scaler']
    if_feature_order = artifacts['if_feature_order']

    X_df_if     = X_df[if_feature_order]
    X_if_scaled = if_scaler.transform(X_df_if)

    if_scores      = iso_forest.decision_function(X_if_scaled)
    if_predictions = iso_forest.predict(X_if_scaled)

    if_scores_flipped = -if_scores
    if_min = if_scores_flipped.min()
    if_max = if_scores_flipped.max()

    if if_max - if_min == 0:
        if_attack_prob = np.zeros(len(if_scores_flipped))
    else:
        if_attack_prob = (if_scores_flipped - if_min) / (if_max - if_min)

    return if_attack_prob, if_predictions


def run_ensemble(X_df: pd.DataFrame, artifacts: dict) -> np.ndarray:
    """
    Run RF + LightGBM + XGBoost, return averaged attack probability.
    """
    prob_xgb  = artifacts['model_xgb'].predict_proba(X_df)[:, 1]
    prob_lgbm = artifacts['model_lgbm'].predict_proba(X_df)[:, 1]
    prob_rf   = artifacts['model_rf'].predict_proba(X_df)[:, 1]

    return (prob_xgb + prob_lgbm + prob_rf) / 3


def combine_and_decide(
    ensemble_prob: np.ndarray,
    if_attack_prob: np.ndarray,
    artifacts: dict
) -> dict:
    """
    Bayesian combination of ensemble + IF scores.
    Returns final verdict dict.
    """
    threshold = artifacts['threshold']

    combined_prob = (ENSEMBLE_WEIGHT * ensemble_prob) + (IF_WEIGHT * if_attack_prob)

    final_predictions = (combined_prob >= threshold).astype(int)

    total_flows   = len(final_predictions)

    attack_ratio  = int(sum(final_predictions == 1)) / len(final_predictions)

    verdict       = 'ATTACK' if attack_ratio >= ATTACK_RATIO_THRESHOLD else 'NORMAL'

    threat_intensity = round(float(combined_prob.mean()) * 100, 1)

    if verdict == 'NORMAL':
        if combined_prob.mean() < 0.4:
            risk_level = 'Low'
            network_status = 'Safe'
            traffic_behavior = 'Stable' if combined_prob.std() < 0.2 else 'Unstable'
            analyst_note = 'Traffic appears normal. No immediate action required.'
        else:
            risk_level = 'Medium'
            network_status = 'Suspicious'
            traffic_behavior = 'Stable' if combined_prob.std() < 0.2 else 'Unstable'
            analyst_note = 'Traffic is normal but some flows show elevated scores. Keep monitoring.'
    else:
        risk_level = 'High'
        network_status = 'Danger'
        traffic_behavior = 'Erratic'
        analyst_note = 'High threat intensity detected. Immediate action recommended.'

    peak_flow_index = int(np.argmax(combined_prob)) + 1
    raw_confidence = abs(float(combined_prob.mean()) - float(threshold))

    return {
        'verdict':           verdict,
        'total_flows':       total_flows,
        'risk_level':        risk_level,
        'network_status':    network_status,
        'threat_intensity':  threat_intensity,
        'traffic_behavior':  traffic_behavior,
        'peak_flow_index':   peak_flow_index,
        'analyst_note':      analyst_note,
        'all_flow_scores':   combined_prob.round(4).tolist(),
        'confidence': round(min(raw_confidence * 250, 100), 1)
    }



def run_prediction(raw_df: pd.DataFrame, artifacts: dict) -> dict:
    """
    Master function.
    Input  : raw_df from feature_extraction.extract_all_features()
             artifacts from load_artifacts()
    Output : result dict with verdict, counts, scores
    """
    X_df           = preprocess(raw_df, artifacts)
    if_attack_prob, _ = run_isolation_forest(X_df, artifacts)
    ensemble_prob  = run_ensemble(X_df, artifacts)
    result         = combine_and_decide(ensemble_prob, if_attack_prob, artifacts)

    return result
