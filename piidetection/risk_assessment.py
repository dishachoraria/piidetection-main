PII_WEIGHTS = {
    'SSN': 50,
    'credit_card': 40,
    'email': 20,
    'name': 5,
    'medical_record': 60,
    'passport_number': 45,
    'geolocation': 20,
    'phone_number': 15,
    'health_data': 50,
    'student_record': 30,
    'ip_address': 15,
    'biometric_data': 70,
    'date_of_birth': 25,
    'financial_data': 55,
    'driver_license': 40
}

COMPLIANCE_PENALTIES = {
    'GDPR': 1.2,  # 20% penalty for non-compliance
    'HIPAA': 1.5, # 50% penalty for non-compliance
    'CCPA': 1.3,  # 30% penalty for non-compliance
    'PCI_DSS': 1.4, # 40% penalty for non-compliance
    'FERPA': 1.3   # 30% penalty for non-compliance
}

def calculate_risk_score(pii_data, volume, compliance_factors):
    """
    Calculate the risk score based on PII sensitivity, volume, and compliance factors.
    """
    risk = 0
    for pii_type, count in pii_data.items():
        weight = PII_WEIGHTS.get(pii_type, 1)
        risk += weight * count

    # Base risk score normalized by data volume
    base_risk_score = (risk / volume)

    # Adjust risk score based on compliance factors (penalty for non-compliance)
    for regulation, compliance in compliance_factors.items():
        if not compliance:
            base_risk_score *= COMPLIANCE_PENALTIES[regulation]

    return base_risk_score

def check_compliance(pii_data):
    """
    Check for compliance with regulations and return compliance status along with warnings.
    """
    warnings = []
    compliance = {
        'GDPR': True,   # Assume compliance unless specific PII is detected
        'HIPAA': True,
        'CCPA': True,
        'PCI_DSS': True,
        'FERPA': True
    }

    # GDPR: General Data Protection Regulation (Europe)
    if 'email' in pii_data or 'name' in pii_data:
        warnings.append("Warning: GDPR compliance may be required for personal data (email, name).")
        compliance['GDPR'] = False
    if 'SSN' in pii_data or 'passport_number' in pii_data:
        warnings.append("Warning: GDPR compliance required for sensitive identification data (SSN, passport number).")
        compliance['GDPR'] = False

    # HIPAA: Health Insurance Portability and Accountability Act (USA)
    if 'medical_record' in pii_data or 'health_data' in pii_data:
        warnings.append("Warning: HIPAA compliance is required for medical records and health-related data.")
        compliance['HIPAA'] = False

    # CCPA: California Consumer Privacy Act (USA)
    if 'geolocation' in pii_data:
        warnings.append("Warning: CCPA compliance required for geolocation data.")
        compliance['CCPA'] = False
    if 'email' in pii_data or 'name' in pii_data:
        warnings.append("Warning: CCPA compliance required for personal information (name, email).")
        compliance['CCPA'] = False

    # PCI DSS: Payment Card Industry Data Security Standard
    if 'credit_card' in pii_data:
        warnings.append("Warning: PCI DSS compliance required for payment card data (credit card information).")
        compliance['PCI_DSS'] = False

    # FERPA: Family Educational Rights and Privacy Act (USA)
    if 'student_record' in pii_data:
        warnings.append("Warning: FERPA compliance required for student education records.")
        compliance['FERPA'] = False

    return compliance, warnings
