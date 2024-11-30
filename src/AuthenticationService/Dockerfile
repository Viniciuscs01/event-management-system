# Etapa 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Copiar arquivos de projeto e restaurar dependências
COPY AuthenticationService.csproj .
RUN dotnet restore

# Copiar todo o conteúdo e compilar o projeto
COPY . .
RUN dotnet publish -c Release -o /app/out

# Etapa 2: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/out .

# Porta exposta
EXPOSE 80

# Comando de inicialização
ENTRYPOINT ["dotnet", "AuthenticationService.dll"]
