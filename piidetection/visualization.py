import matplotlib.pyplot as plt

def plot_pii_distribution(pii_counts):
    """
    Plot the distribution of different PII types in the dataset.
    """
    plt.figure(figsize=(10, 6))
    plt.bar(pii_counts.keys(), pii_counts.values(), color='skyblue')
    plt.title('Distribution of PII Types')
    plt.xlabel('PII Type')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

def plot_risk_levels(risk_scores, compliance_violations=None):
    """
    Plot the risk levels for different datasets/files along with compliance penalties.
    """
    plt.figure(figsize=(10, 6))
    
    # Plot risk levels
    plt.bar(risk_scores.keys(), risk_scores.values(), color='salmon', label='Risk Score')
    
    # If compliance violations are provided, plot as an overlay
    if compliance_violations:
        compliance_penalty_values = list(compliance_violations.values())
        plt.bar(compliance_violations.keys(), compliance_penalty_values, color='orange', alpha=0.6, label='Compliance Penalties')
    
    plt.title('Risk Levels by Dataset/File')
    plt.xlabel('Dataset/File')
    plt.ylabel('Risk Score')
    plt.xticks(rotation=45)
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_pii_risk_contributions(pii_risk_contributions):
    """
    Plot risk contributions by PII type.
    """
    plt.figure(figsize=(10, 6))
    plt.bar(pii_risk_contributions.keys(), pii_risk_contributions.values(), color='lightgreen')
    plt.title('Risk Contributions by PII Type')
    plt.xlabel('PII Type')
    plt.ylabel('Risk Contribution')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
