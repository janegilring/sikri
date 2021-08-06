# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.163.1/containers/alpine/.devcontainer/base.Dockerfile

FROM mcr.microsoft.com/powershell:7.1.3-ubuntu-20.04-20210414

RUN apt-get update && apt-get -y upgrade

# https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-linux?pivots=apt
RUN apt-get install ca-certificates curl apt-transport-https lsb-release gnupg -y

RUN curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null

RUN AZ_REPO=$(lsb_release -cs);echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $AZ_REPO main" | tee /etc/apt/sources.list.d/azure-cli.list

RUN apt-get update && apt-get install azure-cli

#  Install the latest stable Git version: https://itsfoss.com/install-git-ubuntu/
RUN apt install software-properties-common -y && add-apt-repository ppa:git-core/ppa -y && apt update && apt install git -y

################################
# Install Terraform
################################

#RUN apt-get update
#RUN apt-get install -y wget

# Download terraform for linux
#RUN wget --progress=dot:mega https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip

SHELL ["pwsh", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

RUN $ENV:TERRAFORM_VERSION="0.15.4";Invoke-Webrequest https://releases.hashicorp.com/terraform/$($ENV:TERRAFORM_VERSION)/terraform_$($ENV:TERRAFORM_VERSION)_linux_amd64.zip -OutFile /tmp/terraform.zip

RUN Expand-Archive /tmp/terraform.zip -DestinationPath /tmp/terraform


RUN \
	# Unzip
	#unzip terraform_${TERRAFORM_VERSION}_linux_amd64.zip && \
	# Move to local bin
	mv /tmp/terraform/terraform /usr/local/bin/ && \
	# Make it executable
	chmod +x /usr/local/bin/terraform && \
	# Check that it's installed
	terraform --version

RUN Install-Module PSDepend -Force

COPY ["powershell/requirements.psd1", "/tmp/requirements.psd1"]

RUN Invoke-PSDepend /tmp/requirements.psd1 -Force

RUN apt install -y sudo

# Switch to non-root user:
RUN useradd --create-home vscode
RUN usermod -aG sudo vscode
WORKDIR /home/vscode
USER vscode

RUN git config --global core.autocrlf true
RUN git config --global user.name "Jan Egil Ring"
RUN git config --global user.email "jan.egil.ring@crayon.com"
RUN git config --global color.ui true

#RUN Enable-AzContextAutosave