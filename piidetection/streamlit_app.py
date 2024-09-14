import streamlit as st
import pandas as pd
from core import CrafterCmd
from visualization import plot_pii_distribution, plot_risk_levels

# Initialize CrafterCmd
crafter = CrafterCmd()

# Streamlit app layout
st.title("PII Detection System with Risk Assessment")
st.write("Choose one of the options below to scan for PII:")

# Option to choose the method of input
option = st.selectbox(
    "Select Input Method",
    ["Upload CSV File", "PostgreSQL Database", "Google Cloud Storage (GCS)"]
)

# Function to process and visualize PII results
def process_pii_results(pii_results, items):
    # Prepare the PII counts, check if 'entity_type' exists before accessing it
    pii_counts = {}
    for entry in pii_results:
        if 'entity_type' in entry:
            entity_type = entry['entity_type']
            pii_counts[entity_type] = pii_counts.get(entity_type, 0) + 1

    if pii_counts:
        # Plot the PII distribution
        st.write("PII Distribution:")
        plot_pii_distribution(pii_counts)

        # Calculate and plot the risk score
        compliance, warnings = crafter.check_compliance(pii_counts)
        risk_score = crafter.calculate_risk_score(pii_counts, len(items), compliance)
        st.write(f"Risk Score: {risk_score}")
        plot_risk_levels({"Input Data": risk_score})
    else:
        st.write("No PII detected in the input data.")

# Process CSV File Upload
if option == "Upload CSV File":
    uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"])

    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        st.write("Uploaded CSV file:")
        st.dataframe(df)

        # Convert DataFrame to dictionary
        items = df.to_dict(orient="records")

        # Scan the uploaded file for PII
        st.write("Scanning the uploaded file for PII...")
        pii_results = crafter.scan_data(items)
        st.write("Detected PII Entities:")
        st.json(pii_results)

        # Process and visualize results
        process_pii_results(pii_results, items)

# Process PostgreSQL Database Input
if option == "PostgreSQL Database":
    db_name = st.text_input("Database Name")
    user = st.text_input("User")
    password = st.text_input("Password", type="password")
    query = st.text_area("Enter the SQL query")

    if st.button("Scan Database"):
        if db_name and user and password and query:
            st.write("Fetching and scanning data from PostgreSQL...")
            items = crafter.fetch_data_from_db(crafter.connect_postgresql(db_name, user, password), query)
            st.write("Detected PII Entities:")
            pii_results = crafter.scan_data(items)
            st.json(pii_results)

            # Process and visualize results
            process_pii_results(pii_results, items)
        else:
            st.write("Please fill out all database details and query.")

# Process GCS File Input
if option == "Google Cloud Storage (GCS)":
    bucket_name = st.text_input("GCS Bucket Name")
    source_blob_name = st.text_input("GCS Source Blob Name")

    if st.button("Scan GCS File"):
        if bucket_name and source_blob_name:
            st.write("Downloading and scanning the file from GCS...")
            crafter.download_from_gcs(bucket_name, source_blob_name, f"/tmp/{source_blob_name}")
            items = pd.read_csv(f"/tmp/{source_blob_name}").to_dict(orient="records")

            st.write("Detected PII Entities:")
            pii_results = crafter.scan_data(items)
            st.json(pii_results)

            # Process and visualize results
            process_pii_results(pii_results, items)
        else:
            st.write("Please provide both the GCS Bucket Name and Source Blob Name.")
