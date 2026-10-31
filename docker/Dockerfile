# SAGE-IDS application image (API, dashboard, lab services, experiment runner)
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt pyproject.toml README.md ./
COPY sage_ids ./sage_ids
COPY configs ./configs
COPY fixtures ./fixtures
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir -e .
RUN useradd --create-home --uid 10001 sage && mkdir -p /app/data /app/artifacts /app/reports \
    && chown -R sage /app/data /app/artifacts /app/reports
USER sage
EXPOSE 8000 8501
CMD ["uvicorn", "sage_ids.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
