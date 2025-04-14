import requests

if __name__ == "__main__":
    headers = {
        "key": "A3E99D69-0F3E-4361-A81D-488CB65D8E60",
        "token": "0048e26b2abe4d32709c31c284b1dd921f2c9b4c2c1167750964245002c381708960829",
        "Content-Type": "application/json"
    }

    params = {
        "apikey": "user_01JRSH7KAQBPRQYVZ2V0JDSSBM%3A%3AeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdXRoMHx1c2VyXzAxSlJTSDdLQVFCUFJRWVZaMlYwSkRTU0JNIiwidGltZSI6IjE3NDQ2MTM3MDkiLCJyYW5kb21uZXNzIjoiMDVlNDQ3MGItZjM4Yi00ZjNmIiwiZXhwIjoxNzQ5Nzk3NzA5LCJpc3MiOiJodHRwczovL2F1dGhlbnRpY2F0aW9uLmN1cnNvci5zaCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwgb2ZmbGluZV9hY2Nlc3MiLCJhdWQiOiJodHRwczovL2N1cnNvci5jb20ifQ.ZbgMnM7Q1h4MwabrDGnG-kHeELJk6ra6L_HEA_hXNxw",
        "email": "'uexpvptrbu261@hotmail.com'",
        "password": "'049fB9Hbj'",
        "outDate": 10000,
    }

    resp = requests.post("http://43.138.106.92:9000/ai/character/insertCursor", headers=headers, json=params)

    headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InlvdXlvdXllIiwiaWF0IjoxNzQ0NTU3MjA3LCJleHAiOjE3NDQ2NDM2MDd9.oyB_TXGaRyVOX6la8ulS8QHHSW4Nq6mvbYMKCAoX6VE"
    }
    resp = requests.get("http://43.163.96.185:3010/v1/invalid-cookies",headers=headers)

    invalidCookies = resp.json()["invalidCookies"]

    with open('tokens.txt', 'r') as file:
        lines = file.readlines()
        result = ','.join([line.strip() for line in lines])
    print(result)
