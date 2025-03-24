# Use an official lightweight Python image
FROM python:3.12

# Set the working directory inside the container
WORKDIR /app

# Copy all project files into the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 5000 to access Flask
EXPOSE 5000

# Define the command to run the app
CMD ["python", "app.py"]