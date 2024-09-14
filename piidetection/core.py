#!/usr/bin/env python
# -*- coding: utf8 -*-
import json
import logging
import os
import re
from flask import Flask, jsonify, request
import typer
import qddate
import qddate.patterns
import yaml
from tabulate import tabulate
import requests
from transformers import pipeline
import spacy
from presidio_analyzer import AnalyzerEngine
import pandas as pd
from sqlalchemy import create_engine
from google.cloud import storage

from iterable.helpers.detect import open_iterable
from classify.processor import RulesProcessor, BASE_URL
from classify.stats import Analyzer

from visualization import plot_pii_distribution, plot_risk_levels
from risk_assessment import calculate_risk_score, check_compliance

SUPPORTED_FILE_TYPES = ["jsonl", "bson", "csv", "tsv", "json", "xml", 'ndjson', 'avro', 'parquet', 'xls', 'xlsx', 'orc', 'ndjson']
CODECS = ["lz4", 'gz', 'xz', 'bz2', 'zst', 'br', 'snappy']
BINARY_DATA_FORMATS = ["bson", "parquet"]

DEFAULT_piidetection_CONFIGFILE = ".piidetection"
DEFAULT_RULEPATH = ["rules"]

# Initialize Typer app
app = typer.Typer()
rules_app = typer.Typer()
app.add_typer(rules_app, name='rules')

scan_app = typer.Typer()
app.add_typer(scan_app, name='scan')

server_app = typer.Typer()
app.add_typer(server_app, name='server')

# Initialize Flask app
flask_app = Flask("piidetection", static_url_path="/assets")

# Initialize Presidio for structured PII detection
presidio_analyzer = AnalyzerEngine()

# Initialize Hugging Face NER model for unstructured PII
hf_ner = pipeline("ner", model="dslim/bert-base-NER")

# Initialize spaCy model for additional unstructured PII
spacy_nlp = spacy.load("en_core_web_sm")

# Regular expressions for specific PII detection (e.g., SSN, credit cards, Aadhaar, PAN, Driving License)
ssn_pattern = re.compile(r"^([0-6]\d{2}|7[0-6]\d|77[0-2])([ \-]?)(\d{2})\2(\d{4})$")
credit_card_pattern = re.compile(r"^((4\d{3})|(5[1-5]\d{2}))(-?|\040?)(\d{4}(-?|\040?)){3}|^(3[4,7]\d{2})(-?|\040?)\d{6}(-?|\040?)\d{5}")
aadhaar_pattern = re.compile(r"^[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}$")  # Aadhaar regex
pan_pattern = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b")  # PAN regex
driving_license_pattern = re.compile(r"^(([A-Z]{2}[0-9]{2})( )|([A-Z]{2}-[0-9]{2}))((19|20)[0-9][0-9])[0-9]{7}$")  # Indian DL regex
phone_pattern = re.compile(r"((\+*)((0[ -]*)*|((91 )*))((\d{12})+|(\d{10})+))|\d{5}([- ]*)\d{6}")  # Phone number regex
email_pattern = re.compile(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$")


class CrafterCmd(object):
    def __init__(self, remote: str = None, debug: bool = False):
        if debug:
            logging.basicConfig(
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                level=logging.DEBUG,
            )
        self.remote = remote

        if remote is None:
            self.processor = RulesProcessor()
            self.prepare()

    def prepare(self):
        rulepath = []
        filepath = None
        if os.path.exists(DEFAULT_piidetection_CONFIGFILE):
            logging.debug("Local .piidetection config exists. Using it")
            filepath = DEFAULT_piidetection_CONFIGFILE
        elif os.path.exists(
            os.path.join(os.path.expanduser("~"), DEFAULT_piidetection_CONFIGFILE)
        ):
            logging.debug("Home dir .piidetection config exists. Using it")
            filepath = os.path.join(
                os.path.expanduser("~"), DEFAULT_piidetection_CONFIGFILE
            )
        if filepath:
            f = open(filepath, "r", encoding="utf8")
            config = yaml.load(f, Loader=yaml.FullLoader)
            f.close()
            if config:
                if "rulepath" in config.keys():
                    rulepath = config["rulepath"]
        else:
            rulepath = DEFAULT_RULEPATH
        for rp in rulepath:
            self.processor.import_rules_path(rp, recursive=True)
        self.dparser = qddate.DateParser(
            patterns=qddate.patterns.PATTERNS_EN + qddate.patterns.PATTERNS_RU
        )
    
    def scan_data(self, items, limit=1000, contexts=None, langs=None):
        analyzer = Analyzer()
        datastats = analyzer.analyze(
            fromfile=None,
            itemlist=items,
            options={"delimiter": ",", "format_in": None, "zipfile": None},
        )
        datastats_dict = {row[0]: {header: row[idx] for idx, header in enumerate([
            "key", "ftype", "is_dictkey", "is_uniq", "n_uniq", "share_uniq", "minlen", 
            "maxlen", "avglen", "tags", "has_digit", "has_alphas", "has_special", "dictvalues"])} for row in datastats}

        results = self.processor.match_dict(
            items,
            datastats=datastats_dict,
            confidence=5,
            dateparser=self.dparser,
            parse_dates=True,
            limit=limit,
            filter_contexts=contexts,
            filter_langs=langs,
        )

        output = []
        for res in results.results:
            matches = []
            for match in res.matches:
                s = "%s %0.2f" % (match.dataclass, match.confidence)
                if match.format:
                    s += " (%s)" % (match.format)
                matches.append(s)

            output.append({
                'field': res.field,
                'ftype': datastats_dict[res.field]["ftype"],
                'tags': ",".join(datastats_dict[res.field]["tags"]),
                'matches': ",".join(matches),
                'datatype_url': BASE_URL.format(dataclass=res.matches[0].dataclass) if res.matches else ""
            })

        return output

    def detect_pii(self, text):
        """
        Detect PII using Presidio, Hugging Face NER, and regex.
        """
        pii_results = []

        # Step 1: Detect structured PII using Presidio
        presidio_results = presidio_analyzer.analyze(text=text, entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "US_SOCIAL_SECURITY_NUMBER"], language='en')
        for result in presidio_results:
            pii_results.append({
                'entity': text[result.start:result.end],
                'entity_type': result.entity_type,
                'confidence': result.score
            })

        # Step 2: Detect unstructured PII using Hugging Face NER
        hf_ner_results = hf_ner(text)
        for entity in hf_ner_results:
            pii_results.append({
                'entity': entity['word'],
                'entity_type': entity['entity'],
                'confidence': entity['score']
            })

        # Step 3: Detect specific PII patterns using regex (Aadhaar, PAN, DL, SSN, Credit Card)
        ssn_matches = ssn_pattern.findall(text)
        credit_card_matches = credit_card_pattern.findall(text)
        aadhaar_matches = aadhaar_pattern.findall(text)
        pan_matches = pan_pattern.findall(text)
        dl_matches = driving_license_pattern.findall(text)
        phone_matches = phone_pattern.findall(text)
        email_matches = email_pattern.findall(text)

        # Add regex results to pii_results
        for ssn in ssn_matches:
            pii_results.append({
                'entity': ssn,
                'entity_type': 'SSN (Regex)',
                'confidence': 1.0  # Assume high confidence for regex
            })
        
        for phone in phone_matches:
            pii_results.append({
                'entity': phone,
                'entity_type': 'PHONE (Regex)',
                'confidence': 1.0  # Assume high confidence for regex
            })

        for email in email_matches:
            pii_results.append({
                'entity': email,
                'entity_type': 'EMAIL (Regex)',
                'confidence': 1.0  # Assume high confidence for regex
            })

        for credit_card in credit_card_matches:
            pii_results.append({
                'entity': credit_card,
                'entity_type': 'Credit Card (Regex)',
                'confidence': 1.0
            })

        for aadhaar in aadhaar_matches:
            pii_results.append({
                'entity': aadhaar,
                'entity_type': 'Aadhaar (Regex)',
                'confidence': 1.0
            })

        for pan in pan_matches:
            pii_results.append({
                'entity': pan,
                'entity_type': 'PAN (Regex)',
                'confidence': 1.0
            })

        for dl in dl_matches:
            pii_results.append({
                'entity': dl,
                'entity_type': 'Driving License (Regex)',
                'confidence': 1.0
            })

        return pii_results

    # PostgreSQL Integration
    def connect_postgresql(self, db_name, user, password, host='localhost', port=5432):
        """Connect to PostgreSQL database."""
        engine = create_engine(f'postgresql+psycopg2://{user}:{password}@{host}:{port}/{db_name}')
        return engine

    def fetch_data_from_db(self, engine, query):
        """Fetch data from PostgreSQL database."""
        with engine.connect() as conn:
            data = pd.read_sql(query, conn)
        return data

    def scan_db_data(self, db_name, user, password, query, host='localhost', port=5432):
        """Scan data fetched from PostgreSQL."""
        engine = self.connect_postgresql(db_name, user, password, host, port)
        data = self.fetch_data_from_db(engine, query)
        items = data.to_dict(orient='records')
        self.scan_data(items)

    # Google Cloud Storage Integration
    def download_from_gcs(self, bucket_name, source_blob_name, destination_file_name):
        """Download a file from Google Cloud Storage (GCS)."""
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(source_blob_name)
        blob.download_to_filename(destination_file_name)
        print(f"Blob {source_blob_name} downloaded from GCS bucket {bucket_name} to {destination_file_name}.")

    def scan_gcs_file(self, bucket_name, source_blob_name):
        """Download file from GCS and scan it for PII."""
        local_file_name = f"/tmp/{source_blob_name.split('/')[-1]}"
        self.download_from_gcs(bucket_name, source_blob_name, local_file_name)
        self.scan_file(local_file_name)

    def scan_file(
        self,
        filename,
        delimiter=None,
        tagname=None,
        limit=1000,
        encoding=None,
        contexts=None,
        langs=None,
        dformat="short",
        output=None,
    ):
        iterableargs = {}
        if tagname is not None:
            iterableargs['tagname'] = tagname
        if delimiter is not None:
            iterableargs['delimiter'] = delimiter            

        if encoding is not None:
            iterableargs['encoding'] = encoding                         
                   
        try:
            data_file = open_iterable(filename, iterableargs=iterableargs) 
        except Exception as e:
            print('Exception:', e)                 
            print("Unsupported file type.")
            return []
        items = list(data_file)            
        if len(items) == 0:
            print("No records found to process")
            return

        print("Processing file %s" % (filename))

        # Read entire text for PII detection
        text = '\n'.join([str(item) for item in items])
        pii_results = self.detect_pii(text)

        for result in pii_results:
            print(f"Detected entity: {result['entity']}, Type: {result['entity_type']}, Confidence: {result['confidence']}")

        # Prepare PII counts
        pii_counts = {entry['entity_type']: len([res for res in pii_results if res['entity_type'] == entry['entity_type']]) for entry in pii_results}

        # Perform compliance check and calculate FAIR risk score
        compliance, warnings = check_compliance(pii_counts)
        for warning in warnings:
            print(warning)

        volume = len(items)
        risk_score = calculate_risk_score(pii_counts, volume, compliance)
        print(f"Risk Score (FAIR): {risk_score}")

        # Visualization of PII distribution
        plot_pii_distribution(pii_counts)

        data_file.close()
        del items

# Update Flask server routes
@flask_app.route('/')
def home():
    return "Welcome to the piidetection PII Detection API"

@flask_app.route('/status')
def status():
    return jsonify({"status": "Server is running"}), 200

@flask_app.route('/detect_pii', methods=['POST'])
def detect_pii_route():
    data = request.json
    if 'text' not in data:
        return jsonify({"error": "Missing text for PII detection"}), 400
    pii_results = CrafterCmd().detect_pii(data['text'])
    return jsonify(pii_results)

# Route for scanning data from PostgreSQL
@flask_app.route('/scan_db', methods=['POST'])
def scan_db_route():
    data = request.json
    required_keys = ['db_name', 'user', 'password', 'query']
    if not all(key in data for key in required_keys):
        return jsonify({"error": "Missing database connection parameters"}), 400
    CrafterCmd().scan_db_data(data['db_name'], data['user'], data['password'], data['query'], data.get('host', 'localhost'), data.get('port', 5432))
    return jsonify({"message": "Database data scanned successfully"}), 200

# Route for scanning file from GCS
@flask_app.route('/scan_gcs', methods=['POST'])
def scan_gcs_route():
    data = request.json
    required_keys = ['bucket_name', 'source_blob_name']
    if not all(key in data for key in required_keys):
        return jsonify({"error": "Missing GCS parameters"}), 400
    CrafterCmd().scan_gcs_file(data['bucket_name'], data['source_blob_name'])
    return jsonify({"message": "GCS file scanned successfully"}), 200

@server_app.command('run')
def server_run(host='127.0.0.1', port=10399, debug: bool = False):
    """Run the Flask server."""
    flask_app.run(host=host, port=port, debug=debug)