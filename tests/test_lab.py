import json
import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import server
from crypto_lab import encrypt_or_decrypt_message, calculate_matrix_inverse_mod26


# --- Known cipher vectors and trace checks validate the mathematical conventions shown in the interface. ---
class CipherTests(unittest.TestCase):
    def test_caesar_directions_and_normalization(self):
        self.assertEqual(encrypt_or_decrypt_message('Bonjour été!', 'caesar', {'shift':3})['result'],'ERQMRXUHWH')
        encrypted=encrypt_or_decrypt_message('XYZ ABC','caesar',{'shift':4,'direction':'left'})['result']
        self.assertEqual(encrypt_or_decrypt_message(encrypted,'caesar',{'shift':4,'direction':'left'},True)['result'],'XYZABC')

    def test_playfair_known_vector_and_x(self):
        p={'key':'PLAYFAIR EXAMPLE'}
        t=encrypt_or_decrypt_message('HIDE THE GOLD IN THE TREE STUMP','playfair',p)
        self.assertEqual(t['result'],'BMODZBXDNABEKUDMUIXMMOUVIF')
        self.assertEqual(encrypt_or_decrypt_message(t['result'],'playfair',p,True)['result'],t['prepared'])
        t=encrypt_or_decrypt_message('XXX J','playfair',p)
        self.assertEqual(encrypt_or_decrypt_message(t['result'],'playfair',p,True)['result'],t['prepared'])

    def test_hill_known_vector(self):
        p={'matrix':[[6,24,1],[13,16,10],[20,17,15]]}
        self.assertEqual(encrypt_or_decrypt_message('ACT','hill',p)['result'],'POH')
        self.assertEqual(encrypt_or_decrypt_message('POH','hill',p,True)['result'],'ACT')
        for m in [[[3,3],[2,5]],[[1,2,3,4],[0,1,2,3],[0,0,1,2],[0,0,0,1]]]:
            t=encrypt_or_decrypt_message('HELLO WORLD','hill',{'matrix':m})
            self.assertEqual(encrypt_or_decrypt_message(t['result'],'hill',{'matrix':m},True)['result'],t['prepared'])
        with self.assertRaises(ValueError):calculate_matrix_inverse_mod26([[2,0],[0,2]])

    def test_hill_trace_distinguishes_key_inverse_and_operation(self):
        matrices=[[[3,3],[2,5]],[[6,24,1],[13,16,10],[20,17,15]],[[1,2,3,4],[0,1,2,3],[0,0,1,2],[0,0,0,1]]]
        for m in matrices:
            encrypted=encrypt_or_decrypt_message('HELLO','hill',{'matrix':m})
            decrypted=encrypt_or_decrypt_message(encrypted['result'],'hill',{'matrix':m},True)
            self.assertEqual(encrypted['key_matrix'],m)
            self.assertEqual(decrypted['key_matrix'],m)
            self.assertEqual(decrypted['matrix'],calculate_matrix_inverse_mod26(m))
            self.assertEqual(encrypted['matrix'],m)
            self.assertNotEqual(decrypted['key_matrix'],decrypted['inverse'])
            self.assertIn('K⁻¹ × v',decrypted['steps'][0])
            calc=decrypted['inverse_calculation']
            self.assertEqual((calc['det_mod']*calc['scalar_inverse'])%26,1)
            self.assertEqual([[calc['scalar_inverse']*x%26 for x in r] for r in calc['adjugate']],decrypted['inverse'])
        calc=encrypt_or_decrypt_message('HELP','hill',{'matrix':matrices[0]})['inverse_calculation']
        self.assertEqual((calc['determinant'],calc['scalar_inverse'],calc['adjugate']),(9,3,[[5,-3],[-2,3]]))


# --- Each backend test uses a separate temporary database, leaving the presentation's saved data intact. ---
class BackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.old_db=server.DB
        server.DB=Path(self.tmp.name)/'test.sqlite3'
        server.JOBS.clear()
        server.initialize_database_and_demo_accounts()
        server.app.config['TESTING']=True
        self.client=server.app.test_client()

    def tearDown(self):
        server.DB=self.old_db
        self.tmp.cleanup()

    def post_json_request(self,path,**data):return self.client.post(path,json=data)

    def test_shared_counter_and_two_cooldowns_then_block(self):
        now=1000
        with patch('server.time.time',side_effect=lambda:now):
            for cycle in range(3):
                for i in range(3):
                    r=self.post_json_request('/api/login',user='alice',kind=i,password='wrong').get_json()
                if cycle<2:
                    self.assertEqual(r['state'],'cooldown')
                    self.assertEqual(server.get_account_security_status('alice')['failures'],(cycle+1)*3)
                    self.assertEqual(self.post_json_request('/api/login',user='alice',kind=0,password='101').get_json()['state'],'cooldown')
                    now+=10.01
                else:self.assertEqual(r['state'],'blocked')
            self.post_json_request('/api/protection',user='alice',enabled=False)
            self.assertEqual(self.post_json_request('/api/login',user='alice',kind=0,password='101').get_json()['state'],'blocked')
            self.post_json_request('/api/unlock',user='alice')
            self.assertEqual(self.post_json_request('/api/login',user='alice',kind=2,password='a+').get_json()['state'],'success')

    def run_attack_synchronously(self,kind,name='alice'):
        start=server.get_account_security_status(name)['progress'].get(str(kind),0)
        job={'id':'test','user':name,'kind':kind,'state':'running','attempts':0,'candidate':'','found':None,'elapsed':0,'cancel':False,'start_index':start}
        server.run_password_attack(job)
        return job

    def test_attack_and_manual_share_counter(self):
        self.post_json_request('/api/login',user='alice',kind=2,password='wrong')
        job=self.run_attack_synchronously(0)
        self.assertEqual(job['attempts'],2)
        self.assertEqual(job['state'],'cooldown')
        self.assertEqual(server.get_account_security_status('alice')['failures'],3)
        job=self.run_attack_synchronously(0)
        self.assertEqual(job['attempts'],0)

    def test_exhaustive_searches(self):
        self.post_json_request('/api/protection',user='alice',enabled=False)
        for kind,secret in enumerate(server.DEMO['alice']):
            job=self.run_attack_synchronously(kind)
            self.assertEqual(job['state'],'success')
            self.assertEqual(job['found'],secret)
        self.assertEqual(self.run_attack_synchronously(0)['attempts'],6)
        self.assertEqual(self.run_attack_synchronously(1)['attempts'],28)
        self.assertEqual(len(server.ALPHABET),94)

    def test_resume_after_cooldown_without_repeating_candidates(self):
        now=1000
        with patch('server.time.time',side_effect=lambda:now):
            first=self.run_attack_synchronously(0)
            self.assertEqual((first['state'],first['candidate'],first['attempts']),('cooldown','010',3))
            server.initialize_database_and_demo_accounts()  # Saved cursor survives reinitialization.
            self.assertEqual(server.get_account_security_status('alice')['progress']['0'],3)
            now+=10.01
            second=self.run_attack_synchronously(0)
            self.assertEqual(second['start_index'],3)
            self.assertEqual((second['state'],second['attempts'],second['found']),('success',3,'101'))
            self.assertEqual(server.get_account_security_status('alice')['progress']['0'],0)

    def test_seek_generation_matches_exhaustive_dictionary(self):
        from itertools import product
        for alphabet,length in [('01',3),('1234',4),('abc',3)]:
            expected=[''.join(p) for p in product(alphabet,repeat=length)]
            for start in [0,1,2,5,len(expected)//2,len(expected)-1,len(expected)]:
                self.assertEqual(list(server.generate_password_candidates_from_index(alphabet,length,start)),expected[start:])
        # A very large saved index does not require enumerating its predecessors.
        self.assertEqual(next(server.generate_password_candidates_from_index('01',40,2**40-1)),'1'*40)

    def test_speed_protection_shared_and_independent_of_rate_limit(self):
        self.post_json_request('/api/protection',user='alice',enabled=False)
        self.post_json_request('/api/protection',user='alice',setting='speed_protection',enabled=True)
        now=1000
        with patch('server.time.time',side_effect=lambda:now):
            self.post_json_request('/api/login',user='alice',kind=0,password='wrong')
            now+=.1
            self.post_json_request('/api/login',user='alice',kind=1,password='wrong')
            now+=.1
            result=self.post_json_request('/api/login',user='alice',kind=2,password='a+').get_json()
            self.assertEqual(result['state'],'blocked')
            self.assertIn('500 ms',result['account']['block_reason'])
            self.assertEqual(result['account']['failures'],0)
            self.post_json_request('/api/protection',user='alice',setting='speed_protection',enabled=False)
            self.assertEqual(self.post_json_request('/api/login',user='alice',kind=0,password='101').get_json()['state'],'blocked')
            self.post_json_request('/api/unlock',user='alice')
            self.assertEqual(server.get_account_security_status('alice')['block_reason'],'')
            self.assertEqual(self.post_json_request('/api/login',user='alice',kind=0,password='101').get_json()['state'],'success')

    def test_speed_detector_accepts_human_cadence(self):
        self.post_json_request('/api/protection',user='alice',enabled=False)
        self.post_json_request('/api/protection',user='alice',setting='speed_protection',enabled=True)
        now=1000
        with patch('server.time.time',side_effect=lambda:now):
            for i in range(5):
                self.assertEqual(self.post_json_request('/api/login',user='alice',kind=i%3,password='wrong').get_json()['state'],'failure')
                now+=.6
        self.assertFalse(server.get_account_security_status('alice')['blocked'])

    def test_speed_detector_stops_worker_and_shares_manual_history(self):
        self.post_json_request('/api/protection',user='alice',enabled=False)
        self.post_json_request('/api/protection',user='alice',setting='speed_protection',enabled=True)
        with patch('server.time.time',return_value=1000):
            self.post_json_request('/api/login',user='alice',kind=1,password='wrong')
            job=self.run_attack_synchronously(0)
        self.assertEqual((job['state'],job['attempts']),('blocked',2))
        self.assertIn('Activité automatisée',server.get_account_security_status('alice')['block_reason'])

    def test_attack_connect_creates_session_without_second_attempt(self):
        self.post_json_request('/api/protection',user='alice',enabled=False)
        with patch('server.threading.Thread'):
            jid=self.post_json_request('/api/attack',user='alice',kind=0).get_json()['id']
        self.assertEqual(self.post_json_request(f'/api/attack/{jid}/connect').status_code,400)
        server.run_password_attack(server.JOBS[jid])
        stranger=server.app.test_client()
        self.assertEqual(stranger.post(f'/api/attack/{jid}/connect',json={}).status_code,400)
        self.assertEqual(stranger.get(f'/api/attack/{jid}').status_code,400)
        self.assertEqual(self.post_json_request(f'/api/attack/{jid}/connect').get_json()['current'],'alice')
        self.assertEqual(self.client.get('/api/messages').status_code,200)
        self.assertEqual(server.get_account_security_status('alice')['failures'],0)
        self.post_json_request('/api/logout')
        self.assertEqual(self.post_json_request(f'/api/attack/{jid}/connect').status_code,400)

    def test_progress_is_separate_per_account_and_type_and_unlock_resets_it(self):
        server.save_attack_resume_position('alice',0,3)
        server.save_attack_resume_position('alice',1,6)
        server.save_attack_resume_position('bob',0,2)
        self.assertEqual(server.get_account_security_status('alice')['progress'],{'0':3,'1':6})
        self.post_json_request('/api/unlock',user='alice')
        self.assertEqual(server.get_account_security_status('alice')['progress'],{})
        self.assertEqual(server.get_account_security_status('bob')['progress'],{'0':2})

    def test_session_messages_and_recipient_only_decryption(self):
        self.assertEqual(self.client.get('/api/messages').status_code,400)
        self.post_json_request('/api/login',user='alice',kind=0,password='101')
        r=self.post_json_request('/api/messages',recipient='bob',algorithm='hill',params={'matrix':[[3,3],[2,5]]},text='HELP')
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.get_json()['trace']['result'],'HIAT')
        self.assertEqual(self.post_json_request('/api/messages/1/decrypt').status_code,400)
        self.post_json_request('/api/logout')
        self.post_json_request('/api/login',user='charlie',kind=1,password='3412')
        self.assertEqual(self.client.get('/api/messages').get_json()['messages'],[])
        self.assertEqual(self.post_json_request('/api/messages/1/decrypt').status_code,400)
        self.post_json_request('/api/logout')
        self.post_json_request('/api/login',user='bob',kind=2,password='b*')
        self.assertEqual(self.post_json_request('/api/messages/1/decrypt').get_json()['trace']['result'],'HELP')
        with server.open_database_connection() as c:
            row=c.execute('SELECT * FROM messages').fetchone()
            self.assertNotIn('HELP',dict(row).values())

    def test_success_resets_failures_and_restart_persists(self):
        self.post_json_request('/api/login',user='bob',kind=0,password='wrong')
        server.initialize_database_and_demo_accounts()
        self.assertEqual(server.get_account_security_status('bob')['failures'],1)
        self.post_json_request('/api/login',user='bob',kind=1,password='2341')
        self.assertEqual(server.get_account_security_status('bob')['failures'],0)

    def test_invalid_matrix_and_no_self_message(self):
        self.post_json_request('/api/login',user='alice',kind=0,password='101')
        self.assertEqual(self.post_json_request('/api/messages',recipient='bob',algorithm='hill',params={'matrix':[[2,0],[0,2]]},text='HELLO').status_code,400)
        self.assertEqual(self.post_json_request('/api/messages',recipient='alice',algorithm='caesar',params={},text='HELLO').status_code,400)

    def test_password_changes_persist_update_attack_and_preserve_other_formats(self):
        server.save_attack_resume_position('alice',0,3)
        server.save_attack_resume_position('alice',2,7)
        with server.open_database_connection() as c:
            c.execute("UPDATE users SET failures=9,blocked=1,block_reason='test' WHERE name='alice'")
        result=self.post_json_request('/api/passwords',user='alice',kind=2,password='ab*')
        self.assertEqual(result.status_code,200)
        self.assertEqual(server.get_account_security_status('alice')['length'],3)
        self.assertFalse(server.get_account_security_status('alice')['blocked'])
        self.assertEqual(server.get_account_security_status('alice')['failures'],0)
        self.assertEqual(server.get_account_security_status('alice')['progress'],{'0':3})
        server.initialize_database_and_demo_accounts()
        credentials=self.client.get('/api/state').get_json()['credentials']
        self.assertEqual(credentials['alice'],['101','1234','ab*'])
        self.assertEqual(credentials['bob'],server.DEMO['bob'])
        self.assertEqual(self.post_json_request('/api/login',user='alice',kind=2,password='a+').get_json()['state'],'failure')
        self.assertEqual(self.post_json_request('/api/login',user='alice',kind=0,password='101').get_json()['state'],'success')
        self.post_json_request('/api/protection',user='alice',enabled=False)
        job=self.run_attack_synchronously(2)
        self.assertEqual((job['state'],job['found']),('success','ab*'))

    def test_password_formats_and_change_during_attack(self):
        invalid=[(0,'10'),(0,'102'),(1,'123'),(1,'1235'),(2,'a b'),(2,'é'),(2,''),(2,'a'*33),(True,'101')]
        for kind,password in invalid:
            self.assertEqual(self.post_json_request('/api/passwords',user='alice',kind=kind,password=password).status_code,400)
        for kind,password in [(0,'000'),(1,'4444'),(2,'Z+9*')]:
            self.assertEqual(self.post_json_request('/api/passwords',user='alice',kind=kind,password=password).status_code,200)
            self.assertEqual(self.post_json_request('/api/login',user='alice',kind=kind,password=password).get_json()['state'],'success')
        with patch('server.threading.Thread'):
            jid=self.post_json_request('/api/attack',user='bob',kind=0).get_json()['id']
        self.assertEqual(self.post_json_request('/api/passwords',user='bob',kind=0,password='000').status_code,400)
        server.JOBS[jid]['state']='cancelled'

    def test_reset_clears_all_cipher_messages_but_preserves_integrity(self):
        self.assertEqual(self.client.delete('/api/messages').status_code,400)
        self.post_json_request('/api/login',user='alice',kind=0,password='101')
        self.post_json_request('/api/messages',recipient='bob',algorithm='caesar',params={},text='HELLO')
        self.post_json_request('/api/integrity',recipient='bob',text='unchanged')
        self.post_json_request('/api/logout')
        self.post_json_request('/api/login',user='charlie',kind=0,password='110')
        self.post_json_request('/api/messages',recipient='bob',algorithm='caesar',params={},text='OTHER')
        self.assertEqual(self.client.delete('/api/messages').get_json()['deleted'],2)
        with server.open_database_connection() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM messages').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM integrity_messages').fetchone()[0],1)

    def test_integrity_delivery_sha256_tamper_and_restore(self):
        self.post_json_request('/api/login',user='alice',kind=0,password='101')
        original='Bonjour Bob, à 14 h !\n  Merci. '
        sent=self.post_json_request('/api/integrity',recipient='bob',text=original).get_json()['message']
        mid=sent['id']; expected=hashlib.sha256(original.encode('utf-8')).hexdigest()
        self.assertEqual(sent['sent_hash'],expected)
        self.assertEqual(sent['received_hash'],expected)
        self.assertEqual(sent['received_text'],original)
        self.assertTrue(sent['valid'])
        self.assertEqual(self.post_json_request(f'/api/integrity/{mid}/tamper',text='changed').status_code,400)
        self.post_json_request('/api/logout')
        self.post_json_request('/api/login',user='bob',kind=0,password='011')
        received=self.client.get('/api/integrity').get_json()['messages'][0]
        self.assertEqual(received['sent_hash'],expected)
        verified=self.post_json_request(f'/api/integrity/{mid}/verify').get_json()['message']
        self.assertTrue(verified['valid'])
        changed=self.post_json_request(f'/api/integrity/{mid}/tamper',text=original+'!').get_json()['message']
        self.assertFalse(changed['valid'])
        self.assertEqual(changed['sent_hash'],expected)
        self.assertEqual(changed['original_text'],original)
        self.assertNotEqual(changed['received_hash'],expected)
        server.initialize_database_and_demo_accounts()  # Modification survives a restart.
        self.assertFalse(self.post_json_request(f'/api/integrity/{mid}/verify').get_json()['message']['valid'])
        restored=self.post_json_request(f'/api/integrity/{mid}/tamper',restore=True).get_json()['message']
        self.assertTrue(restored['valid'])
        self.assertEqual(restored['received_text'],original)

    def test_integrity_access_validation_and_known_hash(self):
        self.assertEqual(self.client.get('/api/integrity').status_code,400)
        self.post_json_request('/api/login',user='alice',kind=0,password='101')
        for text in ['', '   ', 'a'*4001, 123]:
            self.assertEqual(self.post_json_request('/api/integrity',recipient='bob',text=text).status_code,400)
        self.assertEqual(self.post_json_request('/api/integrity',recipient='alice',text='abc').status_code,400)
        sent=self.post_json_request('/api/integrity',recipient='bob',text='abc').get_json()['message']
        self.assertEqual(sent['sent_hash'],'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        self.post_json_request('/api/logout')
        self.post_json_request('/api/login',user='charlie',kind=0,password='110')
        self.assertEqual(self.client.get('/api/integrity').get_json()['messages'],[])
        self.assertEqual(self.post_json_request('/api/integrity/1/verify').status_code,400)
        self.assertEqual(self.post_json_request('/api/integrity/1/tamper',text='abc!').status_code,400)


if __name__=='__main__':unittest.main()
