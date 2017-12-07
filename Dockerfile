FROM golang:latest

# Install dependencies
RUN apt-get update -y
RUN apt-get install -y libpcap-dev

# Create app directory
WORKDIR /usr/src/app

# Bundle app source
COPY . .

# Get Go dependencies
RUN go get github.com/google/gopacket

# Build the app
RUN go build -o main ./src/

# Launch app#
EXPOSE 7777
CMD [ "./main" ]
