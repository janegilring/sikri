FROM mcr.microsoft.com/dotnet/runtime:6.0.1-focal-arm64v8

RUN apt-get update && apt-get -y upgrade

RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    ca-certificates \
    apt-transport-https \
    lsb-release \
    gnupg \
	curl \
    && rm -rf /var/lib/apt/lists/*

# Prerequisite for .NET Interactive Notebooks: https://marketplace.visualstudio.com/items?itemName=ms-dotnettools.dotnet-interactive-vscode
# https://docs.microsoft.com/en-gb/dotnet/core/install/linux-ubuntu#2004-
#RUN wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && dpkg -i packages-microsoft-prod.deb && rm packages-microsoft-prod.deb
#RUN apt-get update && apt-get install -y dotnet-sdk-6.0

# Download the powershell '.tar.gz' archive
RUN curl -L -o /tmp/powershell.tar.gz https://github.com/PowerShell/PowerShell/releases/download/v7.2.1/powershell-7.2.1-linux-arm64.tar.gz

# Create the target folder where powershell will be placed
RUN mkdir -p /opt/microsoft/powershell/7

# Expand powershell to the target folder
RUN tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7

# Set execute permissions
RUN chmod +x /opt/microsoft/powershell/7/pwsh

# Create the symbolic link that points to pwsh
RUN ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh

RUN useradd --create-home vscode

RUN wget https://github.com/JanDeDobbeleer/oh-my-posh/releases/download/v7.5.1/posh-linux-arm64 -O /usr/local/bin/oh-my-posh
RUN chmod +x /usr/local/bin/oh-my-posh

# Switch to non-root user:
WORKDIR /home/vscode
USER vscode

SHELL ["pwsh","-NoProfile", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

RUN mkdir /home/vscode/.config;mkdir /home/vscode/.config/powershell
RUN Set-Content -Path /home/vscode/.config/powershell/Microsoft.VSCode_profile.ps1 -Value ". /workspaces/tine/.devcontainer/powershell/profile.ps1"
RUN Install-Module -Name PSReadLine -Force -AllowPreRelease

RUN Install-Module PSDepend -Force

COPY ["powershell/requirements.psd1", "/tmp/requirements.psd1"]

RUN Invoke-PSDepend /tmp/requirements.psd1 -Force