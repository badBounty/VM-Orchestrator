from VM_OrchestratorApp.src.utils import mongo


def load_information(vuln_name, language):
    info = mongo.get_observation_for_object(vuln_name, language)
    return info


class Observation:

    def __init__(self, vuln_name, language):

        self.language = language
        if vuln_name is not None:
            info = load_information(vuln_name, language)
            if info is None:
                self.title = None
                self.observation_title = None
                self.observation_note = None
                self.implication = None
                self.recommendation_title = None
                self.recommendation_urls = None
                self.severity = None
                return
            self.title = info['TITLE']
            self.observation_title = info['OBSERVATION']['TITLE']
            self.observation_note = info['OBSERVATION']['NOTE']
            self.implication = info['IMPLICATION']
            self.recommendation_title = info['RECOMMENDATION']['TITLE']
            self.recommendation_urls = info['RECOMMENDATION']['URLS']
            self.severity = info['SEVERITY']
        else:
            self.title = None
            self.observation_title = None
            self.observation_note = None
            self.implication = None
            self.recommendation_title = None
            self.recommendation_urls = None
            self.severity = None