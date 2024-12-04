import os
from bs4 import BeautifulSoup
import re
import replicate
from openai import OpenAI
from typing import List, Optional, Dict, Any
import json
from utils.cv_structure import CV
from urllib.parse import urlparse, urljoin


def refine_structured_content(content: str) -> str:
    lines = content.split('\n')
    refined_content = []
    current_section = ""
    
    relevant_sections = {
        "TITLE", "META_DESCRIPTION", "H2", "H3", "H4", "H5", "P", "LIST"
    }
    
    for line in lines:
        if any(line.startswith(f"[{tag}]") for tag in relevant_sections):
            if line.startswith("[H"):
                current_section = line[1:line.index("]")]
            refined_content.append(line)
        elif line.startswith("[-]") and current_section in ["Skills", "Languages", "Education"]:
            refined_content.append(line)
    
    return "\n".join(refined_content)

def extract_structured_content(html: str, refine: bool = True) -> str:
    soup = BeautifulSoup(html, 'html.parser')
    structured_content = []

    def add_content(tag_name, content):
        if content and content.strip():
            structured_content.append(f"[{tag_name}] {content.strip()}")

    # Extract title
    title = soup.find('title')
    if title:
        add_content("TITLE", title.get_text())

    # Extract meta description
    meta_description = soup.find('meta', attrs={'name': 'description'})
    if meta_description:
        add_content("META_DESCRIPTION", meta_description.get('content', ''))

    # Function to process a tag and its children
    def process_tag(tag):
        if tag.name in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
            add_content(tag.name.upper(), tag.get_text())
        elif tag.name == 'p':
            add_content("P", tag.get_text())
        elif tag.name in ['ul', 'ol']:
            list_items = tag.find_all('li')
            if list_items:
                structured_content.append("[LIST]")
                for item in list_items:
                    add_content("-", item.get_text())
                structured_content.append("[/LIST]")
        elif tag.name == 'a':
            href = tag.get('href', '')
            add_content("LINK", f"{tag.get_text()} ({href})")
        elif tag.name == 'img':
            alt = tag.get('alt', '')
            src = tag.get('src', '')
            add_content("IMAGE", f"{alt} ({src})")
        else:
            for child in tag.children:
                if child.name:
                    process_tag(child)

    # Find main content area, or use body if not found
    main_content = soup.find(['main', 'article', 'div', 'body'])
    if main_content:
        process_tag(main_content)
    else:
        process_tag(soup.body)

    # Extract domain from the HTML
    domain = ""
    base_tag = soup.find('base', href=True)
    if base_tag:
        domain = base_tag['href']
    else:
        # Try to find any absolute URL in the HTML
        for tag in soup.find_all(['a', 'link', 'script', 'img'], href=True, src=True):
            url = tag.get('href') or tag.get('src')
            if url.startswith('http'):
                parsed_url = urlparse(url)
                domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
                break

    # Extract profile picture URL
    profile_picture = soup.find('img', class_=lambda x: x and 'profile' in x.lower())
    if profile_picture:
        src = profile_picture.get('src', '')
        if src:
            if src.startswith('http'):
                full_url = src
            else:
                full_url = urljoin(domain, src)
            add_content("PROFILE_PICTURE", full_url)

    # Join all extracted content
    return (
        refine_structured_content("\n".join(structured_content))
        if refine else "\n".join(structured_content)
    )

def run_model(
        input_text: str,
        model_id: str = "gpt-4o-mini",
        max_chunk_size: int = 10000,
        return_json: bool = True,
        use_openai: bool = True
    ) -> dict:
    """
    Run either OpenAI or Replicate model to generate structured CV content, processing input in chunks.
    """
    chunks = [input_text[i:i+max_chunk_size] for i in range(0, len(input_text), max_chunk_size)]
    
    output = []

    for i, chunk in enumerate(chunks):
        prompt = f"""
        Using the following structured content (part {i+1} of {len(chunks)}) from a professional profile, create or update a CV object. Include all relevant information such as skills, experience, achievements, and any other valuable details for a professional CV.

        Here's the structured content to process:

        {chunk}

        The profile picture must be a URL from the img tag if it exists.

        Please structure your response as a JSON object with the following format:

        {{
            "name": "Full Name",
            "title": "Professional Title",
            "contact": {{
                "email": "email@example.com",
                "phone": "Phone number",
                "location": "City, Country"
            }},
            "profile_picture": "URL of profile picture",
            "summary": "Professional summary",
            "skills": ["Skill 1", "Skill 2", "Skill 3"],
            "experience": [
                {{
                    "title": "Job Title",
                    "company": "Company Name",
                    "date": "Start Date - End Date",
                    "description": "Job description and achievements"
                }}
            ],
            "education": [
                {{
                    "degree": "Degree Name",
                    "institution": "Institution Name",
                    "date": "Graduation Date"
                }}
            ],
            "languages": ["English", "Spanish"],
            "hourly_rate": "$50",
            "portfolio": ["Project 1", "Project 2"],
            "certifications": "Certification Title",
            "testimonials": ["Testimonial 1", "Testimonial 2"]
        }}

        If the content is in a language other than English, keep the values in the original language but translate the keys to English.
        """

        if use_openai:
            client = OpenAI()
            completion = client.chat.completions.create(
                model=model_id,
                messages=[
                    {"role": "system", "content": "Extract the CV information from the given content."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
            )
            output.append(completion.choices[0].message.content)
        else:
            output.append("".join(
                replicate.run(
                    model_id,
                    input={"prompt": prompt}
                )
            ))

    return extract_json_from_text(output) if return_json else output

def extract_json_from_text(json_results: List[str]) -> dict:
    """
    Extract JSON from text.
    """
    try:
        output = {}
        for json_result in json_results:
        
            # Trim the text between the first { and last }
            json_str = json_result[json_result.index('{'):json_result.rindex('}')+1]

            # remove any comma that is located before a closing bracket
            json_str = re.sub(r',(\s*})', r'\1', json_str)
            # remove any comma that is located before a closing array
            json_str = re.sub(r',(\s*])', r'\1', json_str)
            
            json_str = json_str.replace("...", "")

            # Close any open arrays or objects
            open_braces = json_str.count('{')
            close_braces = json_str.count('}')
            open_brackets = json_str.count('[')
            close_brackets = json_str.count(']')
            
            json_str += ']' * (open_brackets - close_brackets)
            json_str += '}' * (open_braces - close_braces)
            parsed_json = json.loads(json_str)
            output.update({k: v for k, v in parsed_json.items() if k not in output and v != ""})
        return output
        
    except:
        cv_data = CV()
        for json_result in json_results:
            chunk_data = CV.model_validate_json(json_result)
            
            # Update cv_data with new information
            for field in cv_data.model_fields:
                if getattr(chunk_data, field):
                    setattr(cv_data, field, getattr(chunk_data, field))
            
            # Merge any extra fields not defined in the model
            for key, value in chunk_data.__dict__.items():
                if key not in cv_data.model_fields:
                    setattr(cv_data, key, value)

        return cv_data.model_dump()

def impute_missing_keys(cv_data: dict) -> dict:
    """
    Impute missing keys in the input JSON to ensure it can be used in generate_pdf_cv().
    
    Args:
        cv_data (dict): The input CV data dictionary.
    
    Returns:
        dict: The CV data dictionary with all necessary keys present.
    """
    default_structure = {
        "name": "N/A",
        "title": "N/A",
        "contact": {
            "email": "N/A",
            "phone": "N/A",
            "location": "N/A"
        },
        "profile_picture": "",
        "summary": "N/A",
        "skills": [],
        "experience": [],
        "education": []
    }
    
    # Recursively update the cv_data with default values
    def update_dict(target, source):
        for key, value in source.items():
            if key not in target:
                target[key] = value
            elif isinstance(value, dict):
                update_dict(target[key], value)
    
    update_dict(cv_data, default_structure)
    
    # Ensure skills is a list of strings if it's empty or a dict
    if not cv_data['skills'] or isinstance(cv_data['skills'], dict):
        cv_data['skills'] = ["N/A"]
    
    # Ensure experience and education are lists of dicts with required keys
    for section in ['experience', 'education']:
        if not cv_data[section]:
            cv_data[section] = [{"title": "N/A", "company": "N/A", "date": "N/A", "description": "N/A"}] if section == 'experience' else [{"degree": "N/A", "institution": "N/A", "date": "N/A"}]
        else:
            for item in cv_data[section]:
                if section == 'experience':
                    item.setdefault('title', "N/A")
                    item.setdefault('company', "N/A")
                    item.setdefault('date', "N/A")
                    item.setdefault('description', "N/A")
                else:  # education
                    item.setdefault('degree', "N/A")
                    item.setdefault('institution', "N/A")
                    item.setdefault('date', "N/A")
    
    return cv_data