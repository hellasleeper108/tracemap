FROM python:3.12-slim
WORKDIR /app
COPY . .
EXPOSE 9999
CMD ["python3", "tracemap.py", "--agent"]
