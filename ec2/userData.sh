#!/bin/bash

TARGET_USER="ec2-user"
BASE="http://127.0.0.1:8080"
EMAIL="admin@gmail.com"
PASSWORD="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)"
COOK="$(mktemp)"

HOME_DIR="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
REPO_DIR="$HOME_DIR/label-studio-ml-backend"
SAM2_DIR="$REPO_DIR/label_studio_ml/examples/segment_anything_2_image"
DATA_DIR="$HOME_DIR/mydata"

echo "$PASSWORD" > "$HOME_DIR/password.txt"
chmod 600 "$HOME_DIR/password.txt"

# Update system
sudo dnf -y update

# Install Docker + deps
sudo dnf -y install docker git libxcrypt-compat jq
sudo systemctl enable docker.service
sudo systemctl enable containerd.service
sudo systemctl start docker

# Install docker-compose
sudo curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

echo "✅ Installed docker, docker-compose, git, libxcrypt, jq"

# Add ec2-user to docker group
sudo usermod -a -G docker "$TARGET_USER"

mkdir -p "$DATA_DIR"
sudo chown -R "$TARGET_USER:$TARGET_USER" "$DATA_DIR"

# Get DEVICE from environment (default to cpu if not set)
DEVICE="${DEVICE:-cpu}"
echo "Using DEVICE: $DEVICE"

sudo -u "$TARGET_USER" -H env DEVICE="$DEVICE" bash -lc "
if [ ! -d \"$REPO_DIR/.git\" ]; then
    git clone https://github.com/HumanSignal/label-studio-ml-backend.git \"$REPO_DIR\"
fi

cd \"$SAM2_DIR\"

# Remove existing docker-compose.yml
if [ -f docker-compose.yml ]; then
    rm -f docker-compose.yml
    echo \"✅ Removed existing docker-compose.yml\"
fi

# Check DEVICE environment variable and download appropriate docker-compose file
echo \"Device type: \$DEVICE\"

if [ \"\$DEVICE\" = \"cpu\" ]; then
    echo \"Downloading docker-compose-cpu.yml...\"
    curl -L -o docker-compose-cpu.yml https://raw.githubusercontent.com/grillhub/padin-setup/main/segment_anything_2_image/docker-compose-cpu.yml
    mv docker-compose-cpu.yml docker-compose.yml
    echo \"✅ Downloaded and renamed docker-compose-cpu.yml to docker-compose.yml\"
elif [ \"\$DEVICE\" = \"cuda\" ]; then
    echo \"Downloading docker-compose-gpu.yml...\"
    curl -L -o docker-compose-gpu.yml https://raw.githubusercontent.com/grillhub/padin-setup/main/segment_anything_2_image/docker-compose-gpu.yml
    mv docker-compose-gpu.yml docker-compose.yml
    echo \"✅ Downloaded and renamed docker-compose-gpu.yml to docker-compose.yml\"
    
    echo \"Downloading setup_cuda.sh...\"
    curl -L -o setup_cuda.sh https://raw.githubusercontent.com/grillhub/padin-setup/main/segment_anything_2_image/setup_cuda.sh
    chmod +x setup_cuda.sh
    echo \"Executing setup_cuda.sh...\"
    bash setup_cuda.sh
    echo \"✅ setup_cuda.sh executed\"
    
    echo \"Downloading verify_cuda.sh...\"
    curl -L -o verify_cuda.sh https://raw.githubusercontent.com/grillhub/padin-setup/main/segment_anything_2_image/verify_cuda.sh
    chmod +x verify_cuda.sh
    echo \"Executing verify_cuda.sh...\"
    bash verify_cuda.sh
    echo \"✅ verify_cuda.sh executed\"
else
    echo \"ERROR: Unknown DEVICE value: \$DEVICE. Expected 'cpu' or 'cuda'.\" >&2
    exit 1
fi

DOCKER_BUILDKIT=1 COMPOSE_DOCKER_CLI_BUILD=1 docker-compose build
COMPOSE_HTTP_TIMEOUT=600 docker-compose up -d

sudo chmod -R 777 \"$DATA_DIR\"

docker run -d -it \
    --name label-studio \
    --restart always \
    -p 8080:8080 \
    -v \"$DATA_DIR\":/label-studio/data \
    -e LABEL_STUDIO_USERNAME=\"$EMAIL\" \
    -e LABEL_STUDIO_PASSWORD=\"$PASSWORD\" \
    heartexlabs/label-studio:latest
"

echo "✅ Installation complete. Access Label Studio at http://<your-ec2-ip>:8080"

#------------------ Get CSRF ------------------
trap 'rm -f "$COOK" login.html jwt_settings.json current_token.json' EXIT

echo "Waiting for Label Studio to respond at $BASE ..."
for i in $(seq 1 30); do
if curl -s -o /dev/null -w "%{http_code}" "$BASE/user/login/" | grep -qE '200|302'; then
    echo "Label Studio is up."
    break
fi
sleep 3
if [ "$i" -eq 30 ]; then
    echo "ERROR: Label Studio did not respond in time." >&2
    exit 1
fi
done

echo "Fetching CSRF cookie ..."
curl -s -c "$COOK" "$BASE/user/login/" -o login.html

CSRF="$(awk '/csrftoken/ {print $7}' "$COOK" | tail -n1)"
if [ -z "${!CSRF:-}" ]; then
echo "ERROR: Failed to capture csrftoken cookie." >&2
exit 1
fi

echo "Logging in as $EMAIL ..."
curl -s -L -b "$COOK" -c "$COOK" \
-H "Referer: $BASE/" \
-H "X-CSRFToken: $CSRF" \
-H "Content-Type: application/x-www-form-urlencoded" \
--data "email=${!EMAIL}&password=${!PASSWORD}&csrfmiddlewaretoken=${!CSRF}" \
"$BASE/user/login/?next=/" -o /dev/null

NEW_CSRF="$(awk '/csrftoken/ {print $7}' "$COOK" | tail -n1)"
SESSIONID="$(awk '/sessionid/ {print $7}' "$COOK" | tail -n1)"
if [ -z "${!SESSIONID:-}" ]; then
echo "ERROR: Login failed; no sessionid returned." >&2
exit 1
fi
echo "Login OK; session established."

#------------------ Enable API tokens ------------------
cat > jwt_settings.json <<'JSON'
{
"api_tokens_enabled": true,
"legacy_api_tokens_enabled": true
}
JSON

echo "Updating JWT/token settings ..."
curl -s -b "$COOK" -c "$COOK" \
-H "Referer: $BASE/" \
-H "X-CSRFToken: $NEW_CSRF" \
-H "Content-Type: application/json" \
-X POST \
--data-binary @jwt_settings.json \
"$BASE/api/jwt/settings" >/dev/null || true

#------------------ Get Legacy Token ------------------
echo "Requesting current user token ..."
curl -s -b "$COOK" -H "Referer: $BASE/" "$BASE/api/current-user/token" > current_token.json

TOKEN="$(jq -r '.token // empty' < current_token.json 2>/dev/null || true)"
if [ -z "$TOKEN" ]; then
TOKEN="$(grep -oE '"token"[[:space:]]*:[[:space:]]*"[^"]+"' current_token.json | sed -E 's/.*"token"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
fi

if [ -z "$TOKEN" ]; then
echo "WARNING: Could not parse token."
cat current_token.json
else
echo "$TOKEN" > "$HOME/token.txt"
echo "✅ Token saved to $HOME/token.txt"
fi

#------------------ Create Project ------------------
if [ ! -f "$HOME/token.txt" ]; then
echo "ERROR: $HOME/token.txt not found (token missing)"
exit 1
fi
TOKEN="$(cat "$HOME/token.txt")"

cat > project.json <<'JSON'
{
    "title": "PADIN",
    "description": "",
    "label_config": "<View>\n<Style>\n  .main {\n    font-family: Arial, sans-serif;\n    background-color: #f5f5f5;\n    margin: 0;\n    padding: 40px 5px 5px 5px;\n  }\n  .container {\n    display: flex;\n    justify-content: space-between;\n    margin-bottom: 20px;\n  }\n  .column {\n    flex: 1;\n    padding: 10px;\n  \tmargin: 5px; \n    background-color: #fff;\n    border-radius: 5px;\n    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);\n    text-align: center;\n  }\n  .column .title {\n    margin: 0;\n    color: #333;\n  }\n  .column .label {\n    margin-top: 10px;\n    padding: 10px;\n    padding-bottom: 7px; \n    background-color: #f9f9f9;\n    border-radius: 3px;\n  }\n  .lsf-labels {\n    margin: 5px 0 0 0; \n  }\n  .image-container {\n    width: 100%;\n    height: 300px;\n    background-color: #ddd;\n    border-radius: 5px;\n  }\n</Style>\n  \n<View className=\"main\">\n  <View className=\"container\">\n    <View className=\"column\">\n      <HyperText value=\"\" name=\"h1\" className=\"help\" inline=\"true\">\n        Brush for manual labeling\n      </HyperText>\n      <View className=\"label\">        \n        <BrushLabels name=\"tag\" toName=\"image\">\n          <Label value=\"Partial\" background=\"#FF0000\" />\n          <Label value=\"Full\" background=\"#0d14d3\" />\n        </BrushLabels>\n      </View>\n    </View>\n    \n    <View className=\"column\">\n      <HyperText value=\"\" name=\"h2\" className=\"help\" inline=\"true\">\n        <span title=\"1. Click purple auto Keypoints/Rectangle icon on toolbar. 2. Click Foreground/Background label here\">\n          Keypoints for auto-labeling\n        </span>\n      </HyperText>\n      <View className=\"label\">\n        <KeyPointLabels name=\"tag2\" toName=\"image\" smart=\"true\">\n          <Label value=\"Partial\" smart=\"true\" background=\"#FFaa00\" showInline=\"true\" />\n          <Label value=\"Full\" smart=\"true\" background=\"#00aaFF\" showInline=\"true\" />\n        </KeyPointLabels>\n      </View>\n    </View>\n    \n    <View className=\"column\">\n      <HyperText value=\"\" name=\"h3\" className=\"help\" inline=\"true\">\n        <span title=\"1. Click purple auto Keypoints/Rectangle icon on toolbar. 2. Click Foreground/Background label here\">\n          Rectangles for auto-labeling\n        </span>\n      </HyperText>\n      <View className=\"label\">\n        <RectangleLabels name=\"tag3\" toName=\"image\" smart=\"true\">\n          <Label value=\"Partial\" background=\"#FF00FF\" showInline=\"true\" />\n          <Label value=\"Full\" background=\"#00FF00\" showInline=\"true\" />\n        </RectangleLabels>\n      </View>\n    </View>\n    \n  </View>\n  \n  <View className=\"image-container\">\n    <Image name=\"image\" value=\"$image\" zoom=\"true\" zoomControl=\"true\" />\n  </View>\n  \n</View>\n</View>",
    "expert_instruction": "",
    "show_instruction": false,
    "show_skip_button": true,
    "enable_empty_annotation": true,
    "show_annotation_history": false,
    "color": "#FFFFFF",
    "maximum_annotations": 1,
    "is_published": false,
    "model_version": "SAM2",
    "is_draft": false,
    "min_annotations_to_start_training": 0,
    "start_training_on_annotation_update": false,
    "show_collab_predictions": true,
    "show_ground_truth_first": false,
    "show_overlap_first": false,
    "overlap_cohort_percentage": 100,
    "control_weights": {
        "tag": {
            "overall": 1.0,
            "type": "BrushLabels",
            "labels": {
                "Partial": 1.0,
                "Full": 1.0
            }
        },
        "tag2": {
            "overall": 1.0,
            "type": "KeyPointLabels",
            "labels": {
                "Partial": 1.0,
                "Full": 1.0
            }
        },
        "tag3": {
            "overall": 1.0,
            "type": "RectangleLabels",
            "labels": {
                "Partial": 1.0,
                "Full": 1.0
            }
        }
    },
    "parsed_label_config": {
        "tag": {
            "type": "BrushLabels",
            "to_name": [
                "image"
            ],
            "inputs": [
                {
                    "type": "Image",
                    "valueType": null,
                    "value": "image"
                }
            ],
            "labels": [
                "Partial",
                "Full"
            ],
            "labels_attrs": {
                "Partial": {
                    "value": "Partial",
                    "background": "#FF0000"
                },
                "Full": {
                    "value": "Full",
                    "background": "#0d14d3"
                }
            }
        },
        "tag2": {
            "type": "KeyPointLabels",
            "to_name": [
                "image"
            ],
            "inputs": [
                {
                    "type": "Image",
                    "valueType": null,
                    "value": "image"
                }
            ],
            "labels": [
                "Partial",
                "Full"
            ],
            "labels_attrs": {
                "Partial": {
                    "value": "Partial",
                    "smart": "true",
                    "background": "#FFaa00",
                    "showInline": "true"
                },
                "Full": {
                    "value": "Full",
                    "smart": "true",
                    "background": "#00aaFF",
                    "showInline": "true"
                }
            }
        },
        "tag3": {
            "type": "RectangleLabels",
            "to_name": [
                "image"
            ],
            "inputs": [
                {
                    "type": "Image",
                    "valueType": null,
                    "value": "image"
                }
            ],
            "labels": [
                "Partial",
                "Full"
            ],
            "labels_attrs": {
                "Partial": {
                    "value": "Partial",
                    "background": "#FF00FF",
                    "showInline": "true"
                },
                "Full": {
                    "value": "Full",
                    "background": "#00FF00",
                    "showInline": "true"
                }
            }
        }
    },
    "evaluate_predictions_automatically": false,
    "config_has_control_tags": true,
    "skip_queue": "REQUEUE_FOR_OTHERS",
    "reveal_preannotations_interactively": false,
    "pinned_at": null,
    "finished_task_number": 0,
    "queue_total": 0,
    "queue_done": 0,
    "config_suitable_for_bulk_annotation": false
}
JSON
echo "✅ Wrote project.json"

AUTH_SCHEME="Token"
HTTP_CODE=$(curl -s -o project_resp.json -w "%{http_code}" \
-X POST "$BASE/api/projects/" \
-H "Authorization: ${!AUTH_SCHEME} ${!TOKEN}" \
-H "Content-Type: application/json" \
--data-binary @project.json)

if [ "$HTTP_CODE" = "401" ]; then
AUTH_SCHEME="Bearer"
HTTP_CODE=$(curl -s -o project_resp.json -w "%{http_code}" \
    -X POST "$BASE/api/projects/" \
    -H "Authorization: ${!AUTH_SCHEME} ${!TOKEN}" \
    -H "Content-Type: application/json" \
    --data-binary @project.json)
fi

PROJECT_ID="$(jq -r '.id // empty' project_resp.json)"
echo "✅ Project created with id: $PROJECT_ID"

#------------------ Connect SAM2 ------------------
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com)

cat > ml_payload.json <<JSON
{"project":${!PROJECT_ID},"title":"SAM2","url":"http://${!PUBLIC_IP}:9090/","auth_method":"NONE","extra_params":"","is_interactive":true}
JSON

curl -s -o ml_resp.json -w "%{http_code}" \
-X POST "$BASE/api/ml" \
-H "Authorization: ${!AUTH_SCHEME} ${!TOKEN}" \
-H "Content-Type: application/json" \
--data-binary @ml_payload.json

echo "✅ SAM2 ML backend registered"

#------------------ Update docker-compose ------------------
API_KEY="$(cat "$HOME/token.txt")"
sudo -u "$TARGET_USER" -H \
SAM2_DIR="$SAM2_DIR" \
PUBLIC_IP="$PUBLIC_IP" \
API_KEY="$API_KEY" \
bash -lc '
    cd "$SAM2_DIR"
    docker-compose down
    grep -q "restart: always" docker-compose.yml || sed -i "/container_name: ml-backend/a\    restart: always" docker-compose.yml
    sed -i "s|LABEL_STUDIO_URL=.*|LABEL_STUDIO_URL=http://$PUBLIC_IP:8080/|" docker-compose.yml
    sed -i "s|LABEL_STUDIO_API_KEY=.*|LABEL_STUDIO_API_KEY=$API_KEY|" docker-compose.yml
    docker-compose up -d
'

echo "✅ Setup complete."