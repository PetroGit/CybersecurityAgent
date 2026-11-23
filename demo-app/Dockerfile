FROM python:3.13-slim
WORKDIR /app
COPY app.py /app/app.py
USER 65534:65534
EXPOSE 8080
CMD ["python", "app.py"]
