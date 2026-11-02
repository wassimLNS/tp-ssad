import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import server
from crypto_lab import transform, inverse


class CipherTests(unittest.TestCase):
    def test_caesar_directions_and_normalization(self):
        self.assertEqual(transform('Bonjour été!', 'caesar', {'shift':3})['result'],'ERQMRXUHWH')
        encrypted=transform('XYZ ABC','caesar',{'shift':4,'direction':'left'})['result']
        self.assertEqual(transform(encrypted,'caesar',{'shift':4,'direction':'left'},True)['result'],'XYZABC')

    def test_playfair_known_vector_and_x(self):
        p={'key':'PLAYFAIR EXAMPLE'}
        t=transform('HIDE THE GOLD IN THE TREE STUMP','playfair',p)
        self.assertEqual(t['result'],'BMODZBXDNABEKUDMUIXMMOUVIF')
        self.assertEqual(transform(t['result'],'playfair',p,True)['result'],t['prepared'])
        t=transform('XXX J','playfair',p)
        self.assertEqual(transform(t['result'],'playfair',p,True)['result'],t['prepared'])

    def test_hill_known_vector(self):
        p={'matrix':[[6,24,1],[13,16,10],[20,17,15]]}
        self.assertEqual(transform('ACT','hill',p)['result'],'POH')
        self.assertEqual(transform('POH','hill',p,True)['result'],'ACT')
        for m in [[[3,3],[2,5]],[[1,2,3,4],[0,1,2,3],[0,0,1,2],[0,0,0,1]]]:
            t=transform('HELLO WORLD','hill',{'matrix':m})
            self.assertEqual(transform(t['result'],'hill',{'matrix':m},True)['result'],t['prepared'])
        with self.assertRaises(ValueError):inverse([[2,0],[0,2]])


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.old_db=server.DB
        server.DB=Path(self.tmp.name)/'test.sqlite3'
        server.JOBS.clear()
        server.init()
        server.app.config['TESTING']=True
        self.client=server.app.test_client()

    def tearDown(self):
        server.DB=self.old_db
        self.tmp.cleanup()

    def post(self,path,**data):return self.client.post(path,json=data)

    def test_shared_counter_and_two_cooldowns_then_block(self):
        now=1000
        with patch('server.time.time',side_effect=lambda:now):
            for cycle in range(3):
                for i in range(3):
                    r=self.post('/api/login',user='alice',kind=i,password='wrong').get_json()
                if cycle<2:
                    self.assertEqual(r['state'],'cooldown')
                    self.assertEqual(server.status('alice')['failures'],(cycle+1)*3)
                    self.assertEqual(self.post('/api/login',user='alice',kind=0,password='101').get_json()['state'],'cooldown')
                    now+=10.01
                else:self.assertEqual(r['state'],'blocked')
            self.post('/api/protection',user='alice',enabled=False)
            self.assertEqual(self.post('/api/login',user='alice',kind=0,password='101').get_json()['state'],'blocked')
            self.post('/api/unlock',user='alice')
            self.assertEqual(self.post('/api/login',user='alice',kind=2,password='a+').get_json()['state'],'success')

    def run_job(self,kind,name='alice'):
        start=server.status(name)['progress'].get(str(kind),0)
        job={'id':'test','user':name,'kind':kind,'state':'running','attempts':0,'candidate':'','found':None,'elapsed':0,'cancel':False,'start_index':start}
        server.worker(job)
        return job

    def test_attack_and_manual_share_counter(self):
        self.post('/api/login',user='alice',kind=2,password='wrong')
        job=self.run_job(0)
        self.assertEqual(job['attempts'],2)
        self.assertEqual(job['state'],'cooldown')
        self.assertEqual(server.status('alice')['failures'],3)
        job=self.run_job(0)
        self.assertEqual(job['attempts'],0)

    def test_exhaustive_searches(self):
        self.post('/api/protection',user='alice',enabled=False)
        for kind,secret in enumerate(server.DEMO['alice']):
            job=self.run_job(kind)
            self.assertEqual(job['state'],'success')
            self.assertEqual(job['found'],secret)
        self.assertEqual(self.run_job(0)['attempts'],6)
        self.assertEqual(self.run_job(1)['attempts'],28)
        self.assertEqual(len(server.ALPHABET),94)

    def test_resume_after_cooldown_without_repeating_candidates(self):
        now=1000
        with patch('server.time.time',side_effect=lambda:now):
            first=self.run_job(0)
            self.assertEqual((first['state'],first['candidate'],first['attempts']),('cooldown','010',3))
            server.init()  # Saved cursor survives reinitialization.
            self.assertEqual(server.status('alice')['progress']['0'],3)
            now+=10.01
            second=self.run_job(0)
            self.assertEqual(second['start_index'],3)
            self.assertEqual((second['state'],second['attempts'],second['found']),('success',3,'101'))
            self.assertEqual(server.status('alice')['progress']['0'],0)

    def test_seek_generation_matches_exhaustive_dictionary(self):
        from itertools import product
        for alphabet,length in [('01',3),('1234',4),('abc',3)]:
            expected=[''.join(p) for p in product(alphabet,repeat=length)]
            for start in [0,1,2,5,len(expected)//2,len(expected)-1,len(expected)]:
                self.assertEqual(list(server.candidates(alphabet,length,start)),expected[start:])
        # A very large saved index does not require enumerating its predecessors.
        self.assertEqual(next(server.candidates('01',40,2**40-1)),'1'*40)

    def test_speed_protection_shared_and_independent_of_rate_limit(self):
        self.post('/api/protection',user='alice',enabled=False)
        self.post('/api/protection',user='alice',setting='speed_protection',enabled=True)
        now=1000
        with patch('server.time.time',side_effect=lambda:now):
            self.post('/api/login',user='alice',kind=0,password='wrong')
            now+=.1
            self.post('/api/login',user='alice',kind=1,password='wrong')
            now+=.1
            result=self.post('/api/login',user='alice',kind=2,password='a+').get_json()
            self.assertEqual(result['state'],'blocked')
            self.assertIn('500 ms',result['account']['block_reason'])
            self.assertEqual(result['account']['failures'],0)
            self.post('/api/protection',user='alice',setting='speed_protection',enabled=False)
            self.assertEqual(self.post('/api/login',user='alice',kind=0,password='101').get_json()['state'],'blocked')
            self.post('/api/unlock',user='alice')
            self.assertEqual(server.status('alice')['block_reason'],'')
            self.assertEqual(self.post('/api/login',user='alice',kind=0,password='101').get_json()['state'],'success')

    def test_speed_detector_accepts_human_cadence(self):
        self.post('/api/protection',user='alice',enabled=False)
        self.post('/api/protection',user='alice',setting='speed_protection',enabled=True)
        now=1000
        with patch('server.time.time',side_effect=lambda:now):
            for i in range(5):
                self.assertEqual(self.post('/api/login',user='alice',kind=i%3,password='wrong').get_json()['state'],'failure')
                now+=.6
        self.assertFalse(server.status('alice')['blocked'])

    def test_speed_detector_stops_worker_and_shares_manual_history(self):
        self.post('/api/protection',user='alice',enabled=False)
        self.post('/api/protection',user='alice',setting='speed_protection',enabled=True)
        with patch('server.time.time',return_value=1000):
            self.post('/api/login',user='alice',kind=1,password='wrong')
            job=self.run_job(0)
        self.assertEqual((job['state'],job['attempts']),('blocked',2))
        self.assertIn('Activité automatisée',server.status('alice')['block_reason'])

    def test_attack_connect_creates_session_without_second_attempt(self):
        self.post('/api/protection',user='alice',enabled=False)
        with patch('server.threading.Thread'):
            jid=self.post('/api/attack',user='alice',kind=0).get_json()['id']
        self.assertEqual(self.post(f'/api/attack/{jid}/connect').status_code,400)
        server.worker(server.JOBS[jid])
        stranger=server.app.test_client()
        self.assertEqual(stranger.post(f'/api/attack/{jid}/connect',json={}).status_code,400)
        self.assertEqual(stranger.get(f'/api/attack/{jid}').status_code,400)
        self.assertEqual(self.post(f'/api/attack/{jid}/connect').get_json()['current'],'alice')
        self.assertEqual(self.client.get('/api/messages').status_code,200)
        self.assertEqual(server.status('alice')['failures'],0)
        self.post('/api/logout')
        self.assertEqual(self.post(f'/api/attack/{jid}/connect').status_code,400)

    def test_progress_is_separate_per_account_and_type_and_unlock_resets_it(self):
        server.save_progress('alice',0,3)
        server.save_progress('alice',1,6)
        server.save_progress('bob',0,2)
        self.assertEqual(server.status('alice')['progress'],{'0':3,'1':6})
        self.post('/api/unlock',user='alice')
        self.assertEqual(server.status('alice')['progress'],{})
        self.assertEqual(server.status('bob')['progress'],{'0':2})

    def test_session_messages_and_recipient_only_decryption(self):
        self.assertEqual(self.client.get('/api/messages').status_code,400)
        self.post('/api/login',user='alice',kind=0,password='101')
        r=self.post('/api/messages',recipient='bob',algorithm='hill',params={'matrix':[[3,3],[2,5]]},text='HELP')
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.get_json()['trace']['result'],'HIAT')
        self.assertEqual(self.post('/api/messages/1/decrypt').status_code,400)
        self.post('/api/logout')
        self.post('/api/login',user='charlie',kind=1,password='3412')
        self.assertEqual(self.client.get('/api/messages').get_json()['messages'],[])
        self.assertEqual(self.post('/api/messages/1/decrypt').status_code,400)
        self.post('/api/logout')
        self.post('/api/login',user='bob',kind=2,password='b*')
        self.assertEqual(self.post('/api/messages/1/decrypt').get_json()['trace']['result'],'HELP')
        with server.db() as c:
            row=c.execute('SELECT * FROM messages').fetchone()
            self.assertNotIn('HELP',dict(row).values())

    def test_success_resets_failures_and_restart_persists(self):
        self.post('/api/login',user='bob',kind=0,password='wrong')
        server.init()
        self.assertEqual(server.status('bob')['failures'],1)
        self.post('/api/login',user='bob',kind=1,password='2341')
        self.assertEqual(server.status('bob')['failures'],0)

    def test_invalid_matrix_and_no_self_message(self):
        self.post('/api/login',user='alice',kind=0,password='101')
        self.assertEqual(self.post('/api/messages',recipient='bob',algorithm='hill',params={'matrix':[[2,0],[0,2]]},text='HELLO').status_code,400)
        self.assertEqual(self.post('/api/messages',recipient='alice',algorithm='caesar',params={},text='HELLO').status_code,400)


if __name__=='__main__':unittest.main()
