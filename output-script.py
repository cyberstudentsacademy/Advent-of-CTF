import os
import re
import urllib.parse

base_dir = './2024'
github_base_url = 'https://github.com/cyberstudentsacademy/Advent-of-CTF/blob/main/2024'
raw_base_url = 'https://raw.githubusercontent.com/cyberstudentsacademy/Advent-of-CTF/refs/heads/main/2024'

def process_readme(folder_name, folder_path):
    readme_path = os.path.join(folder_path, 'README.md')
    if not os.path.exists(readme_path):
        return

    with open(readme_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Extract title from # Heading
    title_match = re.search(r'^#\s+(.*)', content, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else 'Unknown Title'

    # Extract <details> block
    details_match = re.search(r'<details>(.*?)</details>', content, re.DOTALL)
    if not details_match:
        return
    details_content = details_match.group(1)

    # Remove <summary>...</summary>
    details_content = re.sub(r'<summary>.*?</summary>\s*', '', details_content, flags=re.DOTALL)

    # Extract write-up author
    author_match = re.search(r'Write-up by ([^\n<]+)', content)
    author = author_match.group(1).strip() if author_match else 'Unknown'

    # Replace image paths with GitHub raw URLs
    def replace_image(match):
        alt_text = match.group(1)
        image_file = match.group(2)
        encoded_folder = urllib.parse.quote(folder_name)
        return f'![{alt_text}]({raw_base_url}/{encoded_folder}/{image_file})'

    details_content = re.sub(r'!\[([^\]]*)\]\(([^)]+)\)', replace_image, details_content)

    # Frontmatter
    encoded_folder = urllib.parse.quote(folder_name)
    frontmatter = f'''---\ntitle: {title}\nauthor: {author}\noriginal_url: {github_base_url}/{encoded_folder}/README.md\n---\n'''

    output_path = os.path.join(folder_path, '.output.md')
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(frontmatter + '\n' + details_content.strip() + '\n')

# Process each subfolder
for folder_name in sorted(os.listdir(base_dir)):
    folder_path = os.path.join(base_dir, folder_name)
    if os.path.isdir(folder_path):
        process_readme(folder_name, folder_path)
