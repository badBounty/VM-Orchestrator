# pylint: disable=import-error
from cvsslib import calculate_vector, cvss3

def get_cvss3(stringCVSS3):
    # Returns FLOAT CVSS3 Score...
    # It accepts:
    #   AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N
    #   CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N
    return calculate_vector(stringCVSS3, cvss3)[0]
