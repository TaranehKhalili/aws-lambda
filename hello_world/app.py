import os, json, base64, uuid, boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError

print("TABLE_NAME:", os.environ.get("TABLE_NAME"))
print("AWS_REGION:", os.environ.get("AWS_REGION"))

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["TABLE_NAME"])

def _resp(status, body):
    return {"statusCode": status,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(body)}

def _encode_cursor(key):
    if not key:
        return None
    return base64.urlsafe_b64encode(json.dumps(key).encode()).decode()

def _decode_cursor(cursor):
    if not cursor:
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
    except Exception:
        return None

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def lambda_handler(event, context):
    method = event.get("httpMethod")
    path = event.get("path", "")
    qs = event.get("queryStringParameters") or {}

    # List courses
    if method == "GET" and path == "/courses":
        limit = int(qs.get("limit", "10"))
        cursor = _decode_cursor(qs.get("cursor"))
        scan_kwargs = {"Limit": max(1, min(limit, 100))}
        if cursor:
            scan_kwargs["ExclusiveStartKey"] = cursor

        res = table.scan(**scan_kwargs)
        items = res.get("Items", [])
        next_cursor = _encode_cursor(res.get("LastEvaluatedKey"))
        return _resp(200, {"items": items, "next_cursor": next_cursor})

    # Add course
    if method == "POST" and path == "/courses":
        try:
            body = json.loads(event.get("body") or "{}")
        except json.JSONDecodeError:
            return _resp(400, {"message": "Invalid JSON body"})

        title = (body.get("title") or "").strip()
        description = (body.get("description") or "").strip()
        instructor = (body.get("instructor") or "").strip()

        if not title:
            return _resp(400, {"message": "title is required"})

        course_id = str(uuid.uuid4())
        item = {
            "courseId": course_id,
            "title": title,
            "description": description,
            "instructor": instructor,
            "createdAt": _now_iso(),
        }

        try:
            table.put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(courseId)"
            )
        except ClientError as e:
            return _resp(500, {"message": "Failed to create course", "error": str(e)})

        return _resp(201, item)

    return _resp(405, {"message": "Method Not Allowed"})