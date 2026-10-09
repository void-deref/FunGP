import json

class Card:
    def __init__(self, cntr:str, key_set:list[str], key_id:str, iccid:str):
        if len(key_set) != 3 or len(cntr) != 10 or len(key_id) != 2:
            raise ValueError(f'Either cntr, key_set or version have wrong length')
        
        self.cntr = cntr
        self.kic  = key_set[0]
        self.kid  = key_set[1]
        self.kik  = key_set[2]
        self.key_id = key_id
        self.iccid = iccid

    def to_dict(self):
        return {
            'cntr':    self.cntr,
            'key_set': [self.kic, self.kid, self.kik],
            'key_id':  self.key_id,
            'iccid':   self.iccid
        }


class CardDataBase:
    def __init__(self, path_to_card_deck:str):
        self.path = path_to_card_deck
        self.card_dict: dict[str, Card] = {}

    def update_json(self, card_deck:dict[str, Card]):
        with open(self.path, 'w') as jfile:
            json.dump({imsi: card.to_dict() for imsi, card in card_deck.items()}, jfile, indent=4)


    def load_json(self) -> dict[str, Card]:
        curr_file:dict[str, Card] = {}
        
        with open(self.path, 'r') as jfile:
            raw_json  = json.load(jfile)
            curr_file = {str(imsi): Card(**card) for imsi, card in raw_json.items()}
        return curr_file