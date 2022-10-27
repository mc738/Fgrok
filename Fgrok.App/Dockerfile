FROM mcr.microsoft.com/dotnet/runtime:6.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["Fgrok.App/Fgrok.App.fsproj", "Fgrok.App/"]
RUN dotnet restore "Fgrok.App/Fgrok.App.fsproj"
COPY . .
WORKDIR "/src/Fgrok.App"
RUN dotnet build "Fgrok.App.fsproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Fgrok.App.fsproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Fgrok.App.dll"]
