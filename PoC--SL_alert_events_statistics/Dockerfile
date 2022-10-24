FROM python:3.10-bullseye
ADD getAPIData.py /
RUN pip install requests
RUN pip install python-dotenv
RUN pip install psycopg2-binary
CMD python3 getAPIData.py