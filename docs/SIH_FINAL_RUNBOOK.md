# SIH final runbook



```powershell
```


```powershell
```

## 2. Start the stack

```powershell
docker compose up --build
```

Services:
- Frontend: http://localhost:3000
- Backend: http://localhost:8000/docs
- Role 2: http://localhost:8100/docs
- Role 3: http://localhost:8002/docs
- Role 4: http://localhost:8001/docs

## 3. Live lab

Use Role 1 only inside an isolated, authorized lab. Generate benign traffic and controlled scenarios, capture to PCAP, and pass the PCAP to Role 2. Role 2 converts the capture into metadata/features and sends the normalized stream to Backend/Role 3/Role 4. No component is permitted to send a mitigation command or probe a production network.

## 4. What to show judges

1. Data diode / passive architecture.
3. Live Role 1 capture in an isolated lab.
4. Role 2 extraction without payload decryption.
5. Role 3 DDoS/Bot/PortScan detection.
6. Role 4 DNS/encrypted detection using its appropriate specialized datasets.
7. Backend persistence and WebSocket.
8. Frontend investigation/evidence/analytics.

## 5. Data honesty

