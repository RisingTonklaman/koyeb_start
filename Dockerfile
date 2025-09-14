# ---- build stage ----
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
# cache restore
COPY *.csproj ./
RUN dotnet restore --disable-parallel
# build
COPY . .
RUN dotnet publish -c Release -o /out /p:UseAppHost=false

# ---- run stage ----
FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app
# ขนาดเล็กลงอีกนิด ถ้าไม่ใช้ globalization ให้เปิดบรรทัดล่าง
ENV DOTNET_EnableDiagnostics=0 \
    DOTNET_gcServer=1 \
    DOTNET_gcConcurrent=1
# ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
# ฟังบน 0.0.0.0:8080 ให้ตรงกับ Koyeb
ENV ASPNETCORE_URLS=http://0.0.0.0:8080
EXPOSE 8080
COPY --from=build /out .
ENTRYPOINT ["dotnet","Api.dll"]
