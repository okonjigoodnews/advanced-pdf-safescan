#!/bin/bash
cd /home/kali/advanced-pdf-safescan || exit 1
source .venv/bin/activate streamlit run app/ui_streamlit.py
