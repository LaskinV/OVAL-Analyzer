import xml.etree.ElementTree as ET
import os
from xml.dom.minidom import parseString

def parse_criteria_to_string(criteria_elem, ns):
    elements = []


    for child in criteria_elem:
        # Обработка элементов типа criterion
        if child.tag == f"{{{ns['def']}}}criterion":
            comment = child.attrib["comment"]
            test_ref = child.attrib["test_ref"]
            if "Red Hat Enterprise Linux must be installed" not in comment:
                elements.append(f'{comment} (Test ID: {test_ref})')
        # Обработка элементов типа criteria
        elif child.tag == f"{{{ns['def']}}}criteria":
            operator = child.attrib["operator"]
            nested_elements = parse_criteria_to_string(child, ns)
            elements.append(f"({f' {operator} '.join(nested_elements)})")

    return elements

def parse_oval_file(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        content = file.read()
    root = ET.fromstring(content)

    ns = {
        'oval': 'http://oval.mitre.org/XMLSchema/oval-common-5',
        'def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5'
    }

    # Создаем корневой элемент для нового XML
    root_elem = ET.Element("definitions")

    for definition_block in root.findall(".//def:definition", ns)[:3]:
        # Извлекаем информацию
        metadata = definition_block.find(".//def:metadata", ns)
        description = metadata.find("def:description", ns).text
        cve_elements = metadata.findall(".//def:cve", ns)
        bugzilla_link = metadata.find(".//def:bugzilla", ns).attrib["href"]

        # Извлекаем продукты
        affected_products = []
        for cpe in metadata.findall(".//def:cpe", ns):
            affected_products.append(cpe.text)

        # Извлекаем критерии и преобразуем их в строку
        criteria_root = definition_block.find(".//def:criteria", ns)
        criteria_string = ' '.join(parse_criteria_to_string(criteria_root, ns))

        # Создаем новый XML блок для текущего <definition>
        definition = ET.SubElement(root_elem, "definition")

        info = ET.SubElement(definition, "info")
        ET.SubElement(info, "description").text = description
        links = ET.SubElement(info, "links")
        for cve_elem in cve_elements:
            cve_link = cve_elem.attrib["href"]
            cvss3_value = cve_elem.attrib.get("cvss3", None)
            if cvss3_value:
                ET.SubElement(links, "cve", href=cve_link, cvss3=cvss3_value)
            else:
                ET.SubElement(links, "cve", href=cve_link)
        ET.SubElement(links, "bugzilla", href=bugzilla_link)

        affected = ET.SubElement(definition, "affected_products")
        for product in affected_products:
            ET.SubElement(affected, "product").text = product

        criteria_elem = ET.SubElement(definition, "criteria_list")
        ET.SubElement(criteria_elem, "criteria").text = criteria_string

    output_filename = os.path.join(os.path.dirname(filename), "simplified_oval.xml")
    
    xml_string = ET.tostring(root_elem, encoding='utf-8', method='xml')
    dom = parseString(xml_string)
    pretty_xml = dom.toprettyxml(indent="  ")

    with open(output_filename, 'w', encoding='utf-8') as xml_file:
        xml_file.write(pretty_xml)

    print(f"Упрощённая версия: {output_filename}")

filename = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rhel-8.oval.xml')
parse_oval_file(filename)